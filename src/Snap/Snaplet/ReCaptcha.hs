{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE TemplateHaskell           #-}
{-# LANGUAGE DeriveDataTypeable        #-}
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

import           Control.Applicative
import           Control.Exception            (Exception(..),SomeException(..))
import           Control.Lens
import           Control.Monad.CatchIO        (catch, throw)
import           Control.Monad.Trans.Resource (runResourceT)
import           Control.Monad.Except         (MonadError(throwError))
import qualified Data.Aeson                   as JSON
import qualified Data.Aeson.TH                as JSON
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as BSL
import           Data.Foldable                (fold)
import           Data.Monoid
import           Data.Text                    (pack, Text)
import           Data.Typeable
import           Network.Connection           (TLSSettings (..))
import           Network.HTTP.Conduit         as HTTP
import           Network.HTTP.Types
import           Heist
import           Snap

newtype PrivateKey = PrivateKey { fromPrivateKey :: BS.ByteString }
newtype SiteKey    = SiteKey    { fromSiteKey    :: BS.ByteString }
type UserIP        = BS.ByteString
type UserAnswer    = BS.ByteString

data Captcha
  = Success
  -- | Captcha was incorrectly responded to. Contains the errors returned in the JSON object.
  | Errors [Text]

    -- | The server didn't respond with the JSON object required as per https://developers.google.com/recaptcha/docs/verify
  | InvalidServerResponse

    -- | There was no "recaptcha_response_field" parameter set in the user request.
  | MissingResponseParam

  | ConnectionError !HttpException

  | NoAttempt
 deriving (Show, Typeable)

-- | In theory you can create your own ReCaptcha so that it doesn't use the Google API.
-- But by default, in 'initReCaptcha', this is what it does.
data ReCaptcha = ReCaptcha
  { connectionManager :: !Manager
  , recaptchaQuery    :: !(UserIP -> UserAnswer -> HTTP.Request)
  , htmlScript     :: !BS.ByteString
  , htmlWidget        :: !BS.ByteString
  , _captcha          :: !Captcha
  }

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
initReCaptcha :: SiteKey -> PrivateKey -> SnapletInit b ReCaptcha
initReCaptcha (SiteKey site) (PrivateKey key) = makeSnaplet "recaptcha" "ReCaptcha integration" Nothing $ do
  if BS.length key /= 40
    then fail "ReCaptcha: private key must be exactly 40 chars long"
    else do
      -- this has to parse for the snaplet to work at all
      req <- liftIO (parseUrl "https://www.google.com/recaptcha/api/siteverify")
      man <- liftIO (newManager (mkManagerSettings (TLSSettingsSimple False False False) Nothing))
      onUnload (closeManager man)
      return ReCaptcha
        { connectionManager = man
        , recaptchaQuery    = \ip answer ->
            urlEncodedBody
              [ ("secret"   , key)
              , ("response" , answer)
              , ("remoteip" , ip) ]
              req
        , htmlScript        = "<script src='https://www.google.com/recaptcha/api.js' async defer></script>" 
        , htmlWidget        = "<div class='g-recaptcha' data-sitekey='" <> site <> "'></div>"
        , _captcha          = NoAttempt
        }

-- | The reply is a JSON object looking like
-- {
--   "success": true|false,
--   "error-codes": [...]   // optional
-- }
-- see https://developers.google.com/recaptcha/docs/verify
-- 
-- aeson derives this for us with ease
decodeReCaptchaResponse :: HTTP.Response BSL.ByteString -> Maybe ReCaptchaResponse
decodeReCaptchaResponse response = do
  guard (responseStatus  response == Status 200 "OK")
  -- assume everything else is ok...
  JSON.decode (responseBody response)

-- | Get the ReCaptcha result by querying Google's API.
-- 
-- This requires a "recaptcha_response_field" parameter to be set in the current request.
-- 
-- See 'ReCaptchaResult'
getCaptcha :: HasReCaptcha c => Handler b c Captcha
getCaptcha = do
  mresponse <- getParam "recaptcha_response_field"
  case mresponse of
    Just response -> catchHttpError . with' reCaptcha $ do
      manager  <- gets connectionManager
      getQuery <- gets recaptchaQuery
      remoteip <- getsRequest rqRemoteAddr
      response <- liftIO (httpLbs (getQuery remoteip response) manager)
      return $! case decodeReCaptchaResponse response of
        Just obj | success obj -> Success
                 | otherwise   -> Errors (fold (error_codes obj))
        Nothing -> InvalidServerResponse
    Nothing -> return MissingResponseParam
 where
  catchHttpError f = catch f (return . ConnectionError)

withCaptcha
  :: HasReCaptcha c
  => Handler b c () -- ^ Ran on failure
  -> Handler b c () -- ^ Ran on success
  -> Handler b c ()
withCaptcha onFail onSuccess = do
  s <- getCaptcha
  with' reCaptcha (captcha .= s)
  case s of
    Success -> onSuccess
    _       -> onFail

checkCaptcha :: HasReCaptcha c => Handler b c ()
checkCaptcha = withCaptcha
  (fail . show =<< with' reCaptcha (use captcha))
  (return ())

renderCaptcha :: HasReCaptcha c => Handler b c (BS.ByteString, BS.ByteString)
renderCaptcha = with' reCaptcha $ do
  script <- gets htmlScript
  widget <- gets htmlWidget
  return (script, widget)

data Test = Test
  { _recaptcha :: !(Snaplet ReCaptcha)
  }

makeLenses ''Test

instance HasReCaptcha Test where
  reCaptcha = subSnaplet recaptcha

instance HasReCaptcha ReCaptcha where
  reCaptcha = id

pkey = PrivateKey $ BS.replicate 40 (fromIntegral $ fromEnum 'a')
skey = SiteKey "hello"

test :: IO ()
test = serveSnaplet defaultConfig . makeSnaplet "test" "" Nothing $ do
  c <- nestSnaplet "captcha" recaptcha (initReCaptcha skey pkey)
  addRoutes
    [("check", do
         checkCaptcha
         writeText "Verified!")
    ,("widget", do
         (a,b) <- renderCaptcha
         writeBS a
         writeBS b)
    ]

  return (Test c)
