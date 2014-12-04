{-# LANGUAGE DeriveDataTypeable        #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE TemplateHaskell           #-}
-- |
-- Module      : Snap.Snaplet.ReCaptcha
-- Copyright   : (c) Mike Ledger 2014
--               (c) Lars Petersen 2012
--
-- License     : BSD-style
--
-- Maintainer  : mike@quasimal.com, info@lars-petersen.net
-- Stability   : experimental
-- Portability : portable
--
-- This is a snaplet for google's ReCaptcha verification api. This library uses `http-conduit` and keeps connections alive (a maximum of 10). This is an important point in order to avoid denial of service attacks.
--
-- See 'Snap.Snaplet.ReCaptcha.Example' and the docs provided here for example usage.
--

module Snap.Snaplet.ReCaptcha
  ( -- * Snaplet and Initialization
    ReCaptcha ()
  , HasReCaptcha (..)
  , initReCaptcha
  , initReCaptcha'
    -- * Handlers
  , checkCaptcha
  , withCaptcha
  , getCaptcha
    -- * Types
  , Captcha(..)
  , PrivateKey
  , SiteKey
    -- * Extra
  , cstate
  ) where

import qualified Blaze.ByteString.Builder    as Blaze
import           Control.Applicative
import           Control.Exception           (Exception (..),
                                              SomeException (..))
import           Control.Lens
import           Control.Monad.CatchIO       (catch, throw)
import           Control.Monad.Except        (MonadError (throwError))
import           Control.Monad.Reader        (runReaderT)

import qualified Data.Aeson                  as JSON
import qualified Data.Aeson.TH               as JSON
import qualified Data.ByteString.Char8       as BS
import qualified Data.ByteString.Lazy        as BSL
import qualified Data.Configurator           as Conf
import           Data.Text                   (Text, pack)
import           Data.Text.Encoding          (decodeUtf8, encodeUtf8)

import           Data.Foldable               (fold, toList)
import           Data.Monoid
import           Data.Typeable

import           Heist
import           Heist.Compiled

import qualified Network.HTTP.Client.Conduit as HTTP
import qualified Network.HTTP.Conduit        as HTTP (closeManager)

import           Snap
import           Snap.Snaplet.Heist.Compiled

type PrivateKey = BS.ByteString
type SiteKey    = BS.ByteString
type UserIP     = BS.ByteString
type UserAnswer = BS.ByteString

data Captcha
  = Success
  | Failure
  -- | Errors returned by the Captcha. See <https://developers.google.com/recaptcha/docs/verify> for possible error codes. Note that 'Failure' is used for the case that the only error code returned is "invalid-input-response".
  | Errors [Text]
  -- | The server didn't respond with the JSON object required as per <https://developers.google.com/recaptcha/docs/verify>
  | InvalidServerResponse
  -- | There was no "recaptcha_response_field" parameter set in the user request.
  | MissingResponseParam
 deriving (Show, Typeable)

data ReCaptcha = ReCaptcha
  { connectionManager :: !HTTP.Manager
  , recaptchaQuery    :: !(UserIP -> UserAnswer -> HTTP.Request)
  , _cstate           :: !Captcha
  } deriving (Typeable)

makeLenses ''ReCaptcha

class HasReCaptcha b where
  captchaLens :: SnapletLens (Snaplet b) ReCaptcha

instance HasReCaptcha ReCaptcha where
  captchaLens = id

-- This is kinda lame - should we just parse it manually?
data ReCaptchaResponse = ReCaptchaResponse
  { success     :: !Bool
  , error_codes :: !(Maybe [Text])
  }

JSON.deriveJSON JSON.defaultOptions ''Captcha

JSON.deriveFromJSON JSON.defaultOptions
  { JSON.fieldLabelModifier = map $ \c -> case c of
      '_' -> '-'
      _   -> c
  } ''ReCaptchaResponse

initialiser :: Snaplet (Heist b) -> (SiteKey, PrivateKey) -> Initializer b v ReCaptcha
initialiser heist (site,key) = do
  -- this has to parse for the snaplet to work at all
  req <- liftIO (HTTP.parseUrl "https://www.google.com/recaptcha/api/siteverify")
  man <- liftIO HTTP.newManager
  addReCaptchaHeist heist site
  return ReCaptcha
    { connectionManager = man
    , recaptchaQuery    = \ip answer ->
        HTTP.urlEncodedBody
          [ ("secret"   , key)
          , ("response" , answer)
          , ("remoteip" , ip) ]
          req
    , _cstate = Failure
    }

-- | Initialise the 'ReCaptcha' snaplet. You are required to have "site_key" and "secret_key" set in the snaplet's configuration file. See 'initReCaptcha\'' if you don't want to use Snap's snaplet configuration mechanism.
initReCaptcha :: Snaplet (Heist b) -> SnapletInit b ReCaptcha
initReCaptcha heist =
  makeSnaplet "recaptcha" "ReCaptcha integration" Nothing $
    initialiser heist =<< do
      conf <- getSnapletUserConfig
      (,) <$> require conf "site_key"
          <*> require conf "secret_key"
 where
  require conf field = do
    v <- liftIO (Conf.lookup conf field)
    case v of
      Just v' -> return v'
      Nothing -> do
        path <- BS.pack `fmap` getSnapletFilePath
        err  <- errorMsg ("Could not find key " <> encodeUtf8 field <> " in the config " <> path <> "/devel.cfg")
        fail (BS.unpack err)

-- | Same as 'initReCaptcha', but passing the site key and private key explicitly.
initReCaptcha' :: Snaplet (Heist b) -> (SiteKey, PrivateKey) -> SnapletInit b ReCaptcha
initReCaptcha' heist keys =
  makeSnaplet "recaptcha" "ReCaptcha integration" Nothing (initialiser heist keys)

addReCaptchaHeist :: Snaplet (Heist b) -> BS.ByteString -> Initializer b v ()
addReCaptchaHeist heist site = addConfig heist $ mempty &~ do
  scCompiledSplices .= do
    "recaptcha-div"    ## pureSplice id (return div)
    "recaptcha-script" ## pureSplice id (return script)
 where
  script = Blaze.fromByteString
    "<script src='https://www.google.com/recaptcha/api.js' async defer></script>"
  div = Blaze.fromByteString $!
    "<div class='g-recaptcha' data-sitekey='" <> site <> "'></div>"

-- | Get the ReCaptcha result by querying Google's API.
--
-- This requires a "g-recaptcha-response" (POST) parameter to be set in the current request.
--
-- See 'ReCaptchaResult' for possible failure types.
--
-- @
-- do cstate <- getCaptcha
--    case cstate of
--      Success               -> writeText "Congratulations! You have won free gratification."
--      Failure               -> writeText "Incorrect cstate answer."
--      MissingResponseParam  -> writeText "No g-recaptcha-response POST parameter"
--      InvalidServerResponse -> writeText "Did Google change their API?"
--      Errors errs           -> writeText ("Errors: " <> 'T.pack' ('show' errs))
-- @
--
-- This may throw a 'HTTP.HttpException' if there is a connection-related error.
getCaptcha :: HasReCaptcha b => Handler b c Captcha
getCaptcha = do
  mresponse <- getPostParam "g-recaptcha-response"
  case mresponse of
    Just answer -> withTop' captchaLens $ do
      manager  <- gets connectionManager
      getQuery <- gets recaptchaQuery
      remoteip <- getsRequest rqRemoteAddr
      response <- runReaderT (HTTP.httpLbs (getQuery remoteip answer)) manager
      -- The reply is a JSON object looking like
      -- {
      --   "success": true|false,
      --   "error-codes": [...]   // optional
      -- }
      -- see <https://developers.google.com/recaptcha/docs/verify>
      -- we just use aeson and the derived FromJSON instance here
      return $! case JSON.decode (HTTP.responseBody response) of
        Just obj
          | success      obj -> Success
          | invalidInput obj -> Failure
          | otherwise        -> Errors (fold (error_codes obj))
        Nothing -> InvalidServerResponse
    Nothing -> return MissingResponseParam
 where
  invalidInput obj = error_codes obj == Just ["invalid-input-response"]

-- | Run one of two handlers on either failing or succeeding a captcha.
--
-- @
-- 'withCaptcha' banForever $ do
--   postId <- 'getParam' "id"
--   thing  <- 'getPostParam' thing
--   addCommentToDB postId thing
-- @
--
-- See 'getCaptcha'
withCaptcha
  :: HasReCaptcha b
  => Handler b c () -- ^ Ran on failure
  -> Handler b c () -- ^ Ran on success
  -> Handler b c ()
withCaptcha onFail onSuccess = do
  s <- getCaptcha
  withTop' captchaLens (cstate .= s)
  case s of
    Success -> onSuccess
    _       -> onFail

-- | 'pass' if the cstate failed. Logs errors (not incorrect captchas) with 'logError'.
--
-- @ 'checkCaptcha' '<|>' 'writeText' "Captcha failed!" @
--
-- See 'getCaptcha'
checkCaptcha :: HasReCaptcha b => Handler b c ()
checkCaptcha = do
  s <- getCaptcha
  withTop' captchaLens (cstate .= s)
  case s of
    Success   -> return ()
    Failure   -> pass
    someError -> do
      pass
      logError =<< errorMsg (BS.pack (show someError))

errorMsg :: (MonadSnaplet m, Monad (m b v)) => BS.ByteString -> m b v BS.ByteString
errorMsg err = do
  ancestry <- getSnapletAncestry
  name     <- getSnapletName
  return $! showTextList (ancestry++toList name) <> " (ReCaptcha) : " <> err
 where
  showTextList :: [Text] -> BS.ByteString
  showTextList = BS.intercalate "/" . map encodeUtf8
