{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskell       #-}
module Snap.Snaplet.ReCaptcha.Example
  ( -- * Main
    main
  , initSample
    -- * Necessities
  , sampleTemplate
    -- * Implementation
  , initBlog
  ) where
import qualified Blaze.ByteString.Builder    as Blaze
import           Heist
import           Heist.Compiled

import           Snap
import           Snap.Snaplet.Heist.Compiled
import           Snap.Snaplet.ReCaptcha

import           Control.Lens

import qualified Data.ByteString.Char8       as BS
import           Data.Monoid
import           Data.Text                   (Text)

-- | Simple sample snaplet, built using 'ReCaptcha' in order to demonstrate how
-- one might use it in the scenario of adding comments to a blog.
data Sample = Sample
  { _recaptcha :: !(Snaplet ReCaptcha)
  , _heist     :: !(Snaplet (Heist Sample))
  , _blog      :: !(Snaplet Blog)
  }

-- | Not actually a blog
data Blog = Blog
  { _currentPost :: !(Maybe BS.ByteString)
  }

makeLenses ''Sample
makeLenses ''Blog

instance HasReCaptcha Sample where
  captchaLens = subSnaplet recaptcha

instance HasHeist Sample where
  heistLens = subSnaplet heist

-- | A "blog" snaplet which reads hypothetical "posts" by their 'id', routing
-- GET on \/posts\/:id to display a post, and POST on \/posts\/:id to add a
-- comment to them. For loose, useless definitions of "post" and "comment" -
-- this snaplet is only for demonstration purposes.
initBlog :: forall b. (HasReCaptcha b, HasHeist b) => Snaplet (Heist b)
         -> SnapletInit b Blog
initBlog heist = makeSnaplet "blog" "simple blog" Nothing $ do
  me <- getLens

  addRoutes
    -- Hypothetical comments are just sent as POST to the respective post they
    -- are replying to
    [("/posts/:id", method GET displayPost <|> method POST commentOnPost)]

  addConfig heist $ mempty &~ do
    -- Just 'blog-post' to be whatever is in 'post' at the time
    -- (hopefully set by 'displayPost' after being routed to /posts/:id)
    scCompiledSplices .=
      ("blog-post" ## pureSplice Blaze.fromByteString . lift $ do
         post' <- withTop' me (use currentPost)
         case post' of
           Just post -> return post
           Nothing   -> fail "Couldn't find that.")

  return (Blog Nothing)
 where
  displayPost :: Handler b Blog ()
  displayPost = do
    Just postId <- getParam "id"
    currentPost .= Just ("there is no post #" <> postId <> ". only me.")
    render "recaptcha-example" <|> fail "Couldn't load recaptcha-example.tpl"

  commentOnPost :: Handler b Blog ()
  commentOnPost = do
    Just postId  <- getParam "id"
    Just captcha <- getPostParam "g-recaptcha-response"
    checkCaptcha <|> fail "Bad captcha response."
    -- if we reach here, the captcha was OK
    Just name    <- getPostParam "name"
    Just email   <- getPostParam "email"
    Just content <- getPostParam "content"
    writeBS $ BS.concat [postId, " < (", name,", ", email, ", ", content, ")"]

-- | Heist template, written to $PWD\/snaplets\/heist\/recaptcha-example.tpl
--
-- >sampleTemplate ≈
-- >  <html>
-- >   <head>
-- >     <recaptcha-script />
-- >   </head>
-- >   <body>
-- >     <form method='POST'>
-- >       <input type='text' name='name' placeholder='Name'>
-- >       <input type='text' name='email' placeholder='Email'>
-- >       <br>
-- >       <textarea class='field' name='content' rows='20' placeholder='Content'></textarea>
-- >       <br>
-- >       <recaptcha-div />
-- >       <input type='submit' value='Comment'>
-- >     </form>
-- >   </body>
-- >  </html>
--
sampleTemplate :: Text
sampleTemplate =
 "<html>\
 \  <head>\
 \    <recaptcha-script />\
 \  </head>\
 \  <body>\
 \    <form method='POST'>\
 \      <input type='text' name='name' placeholder='Name'>\
 \      <input type='text' name='email' placeholder='Email'>\
 \      <br>\
 \      <textarea class='field' name='content' rows='20' placeholder='Content'></textarea>\
 \      <br>\
 \      <recaptcha-div />\
 \      <input type='submit' value='Comment'>\
 \    </form>\
 \  </body>\
 \</html>"

-- | Requires 'snaplets/heist/templates/sample.tpl' - a suggested version of which
-- is available in this module as 'sampleTemplate'.
--
-- This simple asks for your site and private key through stdin.
initSample :: SnapletInit Sample Sample
initSample = makeSnaplet "sample" "" Nothing $ do
  h <- nestSnaplet "heist"  heist     (heistInit "templates")
  c <- nestSnaplet "submit" recaptcha (initReCaptcha (Just h))
  t <- nestSnaplet "blog"   blog      (initBlog h)
  return (Sample c h t)

-- | @ 'main' = 'serveSnaplet' 'defaultConfig' 'initSample' @
--
-- You can load this into GHCi and run it, with full logging to stdout/stderr
--
-- >>> :main --verbose --access-log= --error-log=
main :: IO ()
main = serveSnaplet defaultConfig initSample
