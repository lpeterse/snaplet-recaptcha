{-# LANGUAGE OverloadedStrings, FlexibleInstances, MultiParamTypeClasses, TemplateHaskell #-}
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
       , verifyCaptcha
         -- * Types
       , PrivateKey
       , ReCaptchaResult (..)
       ) where

import Data.Lens.Common
import Data.Lens.Template

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL

import Data.Monoid
import Control.Applicative
import Control.Failure
import Control.Exception (throw, try)
import Control.Monad.Trans.Resource (runResourceT)

import Network.HTTP.Types (renderSimpleQuery)
import Network.HTTP.Conduit as HTTP
import Snap

data ReCaptcha
  = ReCaptcha
    { privateKey        :: PrivateKey
    , connectionManager :: Manager 
    }

class HasReCaptcha b where
  recaptchaLens :: Lens (Snaplet b) (Snaplet ReCaptcha)

type PrivateKey = BS.ByteString

-- | The private key must be 40 characters long and encoded just like you get it from Google. 
initReCaptcha :: PrivateKey -> SnapletInit b ReCaptcha
initReCaptcha key
  = makeSnaplet
      "ReCaptcha"
      ""
      Nothing
      $ do man <- liftIO (newManager def)
           if BS.length key /= 40
             then fail "ReCaptcha: private key must be exactly 40 chars long"
             else return $ ReCaptcha key man

data ReCaptchaResult
  = Success
  -- Taken from the official ReCaptcha Api documentation
  | Failure BSL.ByteString
  | ConnectionError HttpException
  -- Misc
  | MissingArguments

instance Failure HttpException (Handler b ReCaptcha) where
  failure = throw

-- | You may use captcha verification troughout your whole application like this:
--
-- > myHandler :: (HasReCaptcha b) => Handler b SomeSubSnaplet ()
-- > myHandler
-- >   = do c <- verifyCaptcha
-- >        case c of
-- >          Success   -> .. -- captcha successfully solved
-- >          _         -> .. -- something went wrong
--
-- You don't need to extract the challenge and response paramters from the request. This is all handled by the snaplet. Just make sure the parameters `recaptcha_challenge_field` and `recaptcha_response_field` are contained in the user's request. Otherwise the `verifyCaptcha` call will return `MissingArguments`.
--
verifyCaptcha :: (HasReCaptcha b) => Handler b c ReCaptchaResult 
verifyCaptcha
  = do mchallenge <- getParam "recaptcha_challenge_field"
       mresponse  <- getParam "recaptcha_response_field"
       case (mchallenge, mresponse) of
         (Just challenge, Just response)
           -> do man         <- withTop' recaptchaLens (gets connectionManager)
                 privatekey  <- withTop' recaptchaLens (gets privateKey)
                 rq          <- withTop' recaptchaLens (parseUrl "http://www.google.com/recaptcha/api/verify")
                 remoteip    <- rqRemoteAddr <$> getRequest
                 let request = rq
                               { HTTP.method = "POST"
                               , queryString = renderSimpleQuery False
                                                 [ ("privatekey", privatekey)
                                                 , ("remoteip",   remoteip)
                                                 , ("challenge",  challenge)
                                                 , ("response",   response)
                                                 ]
                               }
                 result <- liftIO $ Control.Exception.try $ runResourceT $ httpLbs request man
                 case result of
                   Left e   -> do return (ConnectionError (e :: HttpException))
                   Right r  -> do let ls = BSL.split 0x0a $ responseBody r
                                  let ua = return (Failure $ responseBody r)
                                  if length ls < 2
                                    then ua
                                    else case ls !! 0 of
                                           "true"  -> return $ Success
                                           "false" -> return $ Failure (ls !! 1) 
                                           _       -> ua
         _ -> return MissingArguments

