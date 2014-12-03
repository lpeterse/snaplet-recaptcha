{-# LANGUAGE DeriveDataTypeable        #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE TemplateHaskell           #-}
-- |
-- Module      : Snap.Snaplet.ReCaptcha
-- Copyright   : (c) Lars Petersen 2012
-- License     : BSD-style
--
-- Maintainer  : info@lars-petersen.net
-- Stability   : experimental
-- Portability : portable
--
-- This is a snaplet for google's ReCaptcha verification api. This library uses `http-conduit` and keeps connections alive (a maximum of 10 by now). This is an important point in order to avoid denial of service attacks.
--
-- Include it into your application like this:
--
-- > import Snap.Snaplet.ReCaptcha
-- >
-- > data MyApplication = MyApplication { _recaptcha :: Snaplet ReCaptcha, ... }
-- >
-- > $(makeLenses [''MyApplication])
-- >
-- > instance HasReCaptcha MyApplicaiton where
-- >   recaptchaLens = subSnaplet recaptcha
-- >
-- > myApplication :: SnapletInit MyApplication
-- > myApplication
-- >   = makeSnaplet
-- >       "MyApplication"
-- >       ""
-- >        Nothing
-- >        $ do r <- embedSnaplet "recaptcha" recaptcha $ initReCaptcha "YOUR_PRIVATE_KEY"
-- >             return $ MyApplication { _recaptcha = r, ... }
--

module Snap.Snaplet.ReCaptcha
       ( -- * Snaplet and Initialization
         ReCaptcha ()
       , HasReCaptcha (..)
       , initReCaptcha
         -- * Handlers
       , checkCaptcha
       , withCaptcha
       , getCaptcha
         -- * Types
       , PrivateKey
       , Captcha (..)
       ) where

import           Blaze.ByteString.Builder     (Builder, fromByteString)
import           Control.Applicative
import           Control.Exception            (Exception (..),
                                               SomeException (..))
import           Control.Lens
import           Control.Monad.CatchIO        (catch, throw)
import           Control.Monad.Except         (MonadError (throwError))
import           Control.Monad.Trans.Resource (runResourceT)
import qualified Data.Aeson                   as JSON
import qualified Data.Aeson.TH                as JSON
import qualified Data.ByteString.Char8        as BS
import qualified Data.ByteString.Lazy         as BSL
import           Data.Foldable                (fold, toList)
import           Data.Monoid
import           Data.Text                    (Text, pack)
import           Data.Text.Encoding           (decodeUtf8, encodeUtf8)
import           Data.Typeable
import           Heist
import           Heist.Compiled
import           Network.Connection           (TLSSettings (..))
import qualified Network.HTTP.Conduit         as HTTP
import           Snap
import           Snap.Snaplet.Heist.Compiled

type PrivateKey    = BS.ByteString
type SiteKey       = BS.ByteString
type UserIP        = BS.ByteString
type UserAnswer    = BS.ByteString

data Captcha
  = Success
  | Failure
  -- | Errors returned by the Captcha. See <https://developers.google.com/recaptcha/docs/verify> for possible error codes. Note that 'Failure' is used for the case that the only error code returned is "invalid-input-response".
  | Errors [Text]
  -- | The server didn't respond with the JSON object required as per <https://developers.google.com/recaptcha/docs/verify>
  | InvalidServerResponse
  -- | There was no "recaptcha_response_field" parameter set in the user request.
  | MissingResponseParam
  | ConnectionError !HTTP.HttpException
 deriving (Show, Typeable)

data ReCaptcha = ReCaptcha
  { connectionManager :: !HTTP.Manager
  , recaptchaQuery    :: !(UserIP -> UserAnswer -> HTTP.Request)
  , _captcha          :: !Captcha
  } deriving (Typeable)

makeLenses ''ReCaptcha

class HasReCaptcha b where
  reCaptcha :: SnapletLens (Snaplet b) ReCaptcha

data ReCaptchaResponse = ReCaptchaResponse
  { success     :: !Bool
  , error_codes :: !(Maybe [Text])
  }

JSON.deriveFromJSON
  JSON.defaultOptions
    { JSON.fieldLabelModifier = map $ \c -> case c of
         '_' -> '-'
         _   -> c
    }
  ''ReCaptchaResponse

-- | The private key must be 40 characters long and encoded just like you get it from Google.
initReCaptcha
  :: Snaplet (Heist b)
  -> SiteKey -> PrivateKey
  -> SnapletInit b ReCaptcha
initReCaptcha heist site key = makeSnaplet "recaptcha" "ReCaptcha integration" Nothing $ do
  -- this has to parse for the snaplet to work at all
  req <- liftIO (HTTP.parseUrl "https://www.google.com/recaptcha/api/siteverify")
  man <- liftIO (HTTP.newManager (HTTP.mkManagerSettings (TLSSettingsSimple False False False) Nothing))
  onUnload (HTTP.closeManager man)
  addReCaptchaHeist heist site
  return ReCaptcha
    { connectionManager = man
    , recaptchaQuery    = \ip answer ->
        HTTP.urlEncodedBody
          [ ("secret"   , key)
          , ("response" , answer)
          , ("remoteip" , ip) ]
          req
    , _captcha = Failure
    }

addReCaptchaHeist :: Snaplet (Heist b) -> BS.ByteString -> Initializer b v ()
addReCaptchaHeist heist site = addConfig heist $ mempty &~ do
  scCompiledSplices .= do
    "recaptcha-div"    ## builder (div <$> lift (snapletURL =<< getsRequest rqPathInfo))
    "recaptcha-script" ## builder (return script)
 where
  script :: Builder
  script = fromByteString $
    "<script src='https://www.google.com/recaptcha/api.js' async defer></script>"

  div :: BS.ByteString -> Builder
  div action = fromByteString $
    "<div class='g-recaptcha' data-sitekey='" <> site <> "'></div>"

  builder :: Monad n => RuntimeSplice n Builder -> Splice n
  builder = pureSplice id

-- | The reply is a JSON object looking like
-- {
--   "success": true|false,
--   "error-codes": [...]   // optional
-- }
-- see <https://developers.google.com/recaptcha/docs/verify>
--
-- aeson derives this for us with ease
decodeReCaptchaResponse :: HTTP.Response BSL.ByteString -> Maybe ReCaptchaResponse
decodeReCaptchaResponse response = JSON.decode (HTTP.responseBody response)

-- | Get the ReCaptcha result by querying Google's API.
--
-- This requires a "g-recaptcha-response" (POST) parameter to be set in the current request.
--
-- See 'ReCaptchaResult' for possible failure types.
--
-- @ do captcha <- getCaptcha
--      case captcha of
--        Success               -> writeText "Congratulations! You have won free gratification."
--        Failure               -> writeText "Incorrect captcha answer."
--        MissingResponseParam  -> writeText "No g-recaptcha-response POST parameter"
--        InvalidServerResponse -> writeText "Did Google change their API?"
--        Errors errs           -> writeText ("Errors: " <> 'T.pack' ('show' errs))
-- @
getCaptcha :: HasReCaptcha b => Handler b c Captcha
getCaptcha = do
  mresponse <- getPostParam "g-recaptcha-response"
  case mresponse of
    Just response -> catchHttpError . withTop' reCaptcha $ do
      manager  <- gets connectionManager
      getQuery <- gets recaptchaQuery
      remoteip <- getsRequest rqRemoteAddr
      response <- liftIO (HTTP.httpLbs (getQuery remoteip response) manager)
      return $! case decodeReCaptchaResponse response of
        Just obj
          | success      obj -> Success
          | invalidInput obj -> Failure
          | otherwise        -> Errors (fold (error_codes obj))
        Nothing -> InvalidServerResponse
    Nothing -> return MissingResponseParam
 where
  invalidInput obj = error_codes obj == Just ["invalid-input-response"]
  catchHttpError f = catch f (return . ConnectionError)

-- | Run one of two handlers on either failing or succeeding a captcha.
--
-- @ 'withCaptcha' banForever $ do
--      postId <- 'getParam' "id"
--      thing  <- 'getPostParam' thing
--      addCommentToDB postId thing
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
  withTop' reCaptcha (captcha .= s)
  case s of
    Success -> onSuccess
    _       -> onFail

-- | 'pass' if the captcha failed. Logs errors (not incorrect captchas) with 'logError'.
--
-- @ 'checkCaptcha' '<|>' 'writeText' "Captcha failed!" @
--
-- See 'getCaptcha'
checkCaptcha :: HasReCaptcha b => Handler b c ()
checkCaptcha = do
  s <- getCaptcha
  withTop' reCaptcha (captcha .= s)
  case s of
    Success   -> return ()
    Failure   -> pass
    someError -> do
      ancestry <- getSnapletAncestry
      name     <- getSnapletName
      logError (showTextList (ancestry++toList name) <> " (ReCaptcha) : " <> BS.pack (show someError))
      pass
 where
  showTextList = BS.intercalate "/" . map encodeUtf8

data Test = Test
  { _recaptcha :: !(Snaplet ReCaptcha)
  , _heist     :: !(Snaplet (Heist Test))
  , _blog      :: !(Snaplet Blog)
  }

data Blog = Blog

initBlog :: (HasReCaptcha b, HasHeist b) => SnapletInit b Blog
initBlog = makeSnaplet "blog" "simple blog" Nothing $ do
  addRoutes [("/posts/:id", method GET displayPost <|> method POST commentOnPost)]
  return Blog
 where
  displayPost = do
    postId <- getParam "id"
    liftIO (print postId)
    render "test"

  commentOnPost = do
    Just postId  <- getParam "id"
    Just captcha <- getPostParam "g-recaptcha-response"
    response     <- checkCaptcha
    writeBS ("Captcha response: " <> BS.pack (show response))
    writeBS "\r\n"
    Just name    <- getPostParam "name"
    Just email   <- getPostParam "email"
    Just content <- getPostParam "content"
    writeBS $ BS.concat [postId, " < ", name,", ", email, ", ", content]

makeLenses ''Test

instance HasReCaptcha Test where
  reCaptcha = subSnaplet recaptcha

instance HasReCaptcha ReCaptcha where
  reCaptcha = id

instance HasHeist Test where
  heistLens = subSnaplet heist

main :: IO ()
main = serveSnaplet defaultConfig . makeSnaplet "test" "" Nothing $ do
  skey <- liftIO BS.getLine
  pkey <- liftIO BS.getLine
  h    <- nestSnaplet "heist"  heist     (heistInit "templates")
  c    <- nestSnaplet "submit" recaptcha (initReCaptcha h skey pkey)
  t    <- nestSnaplet "blog"   blog      (initBlog)
  return (Test c h t)
