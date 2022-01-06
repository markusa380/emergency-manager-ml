{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

module Lib (
    startApp,
) where

import Control.Monad.IO.Class
import Data.Aeson
import Data.Aeson.TH
import Database.MongoDB (
    Action,
    Pipe,
    access,
    auth,
    close,
    connect,
    host,
    master,
 )
import Network.Wai.Handler.Warp
import Servant

import qualified Mongo
import qualified Users

data Auth = Auth
    { username :: String
    , password :: String
    }
    deriving (Eq, Show)

$(deriveJSON defaultOptions ''Auth)

type API =
    "api" :> "login"
        :> ReqBody '[JSON] Auth
        :> Post '[JSON] (Headers '[Header "Set-Cookie" String] NoContent)

startApp :: IO ()
startApp = do
    _ <- putStrLn "Server started."
    pipe <- connect (host "127.0.0.1")
    _ <- access pipe master "admin" $ auth "backend" "pass"
    run 8080 $ serve api $ server $ Mongo.execution pipe
    close pipe

api :: Proxy API
api = Proxy

server :: Mongo.Execution -> Server API
server mongo =
    login
  where
    login :: Auth -> Handler (Headers '[Header "Set-Cookie" String] NoContent)
    login auth = do
        maybeToken <- liftIO $ Users.login mongo auth.username auth.password
        case maybeToken of
            Just token -> pure $ addHeader cookie NoContent
              where
                cookie = "token=" ++ token ++ "; Max-Age=" ++ show Users.maxTokenAgeSec
            Nothing ->
                throwError
                    err400 {errBody = "Username or password incorrect"}
