{-# LANGUAGE OverloadedStrings, FlexibleInstances, MultiParamTypeClasses, TemplateHaskell #-}
module Main where

import Data.Lens.Common
import Data.Lens.Template

import qualified Data.ByteString             as BS
import qualified Data.ByteString.Lazy        as BSL
import qualified Data.Text                   as T
import qualified Data.Text.Encoding          as T
import           Text.Blaze.Html5            as H
import           Text.Blaze.Html5.Attributes as A
import           Data.Monoid
import           Control.Applicative
import           Text.Blaze.Renderer.Utf8 (renderHtml)

import Snap
import Snap.Snaplet.ReCaptcha

data ReCaptchaTest
  = ReCaptchaTest
    { _recaptcha :: Snaplet ReCaptcha
    }

$(makeLenses [''ReCaptchaTest])

instance HasReCaptcha ReCaptchaTest where
  recaptchaLens = subSnaplet recaptcha

main :: IO ()
main
  = do putStrLn "Please enter your ReCaptcha public key:"
       puk <- getLine
       putStrLn "Please enter your ReCaptcha private key:"
       prk <- T.encodeUtf8 <$> T.pack <$> getLine
       putStrLn "Now point your browser to localhost:8000!"
       serveSnaplet defaultConfig (snaplet puk prk)
  where
    snaplet puk prk 
      = makeSnaplet
                "ReCaptchaTest"
                ""
                Nothing
                $ do r <- embedSnaplet "recaptcha" recaptcha $ initReCaptcha prk
                     addRoutes [("",       writeLBS $ renderHtml $ template puk)
                               ,("verify", do r <- verifyCaptcha
                                              case r of
                                                Success           -> writeBS "Success."
                                                Failure x         -> writeBS "Failure: " >> writeLBS x
                                                ConnectionError x -> writeBS "ConnectionError: "  >> writeText (T.pack $ show x)
                                                MissingArguments  -> writeBS "MissingArguments"
                                )
                               ] 
                     return (ReCaptchaTest r) 
    template puk
      = H.docTypeHtml
         $ do H.head
               $ do H.script ""
                     ! A.type_ "text/javascript"
                     ! A.src   "http://www.google.com/recaptcha/api/js/recaptcha_ajax.js"
              H.body
               ! A.onload ( "Recaptcha.create('" `mappend` toValue puk `mappend` "', 'recaptcha');" )
               $ do H.form
                     ! A.action "verify"
                     ! A.method "POST"
                     $ do H.div ""
                           ! A.id "recaptcha"
                          H.button "Test"
