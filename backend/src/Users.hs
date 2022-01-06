{-# LANGUAGE RankNTypes #-}

module Users (
    login,
    challenge,
) where

import Prelude hiding (lookup)

import Database.MongoDB

import Control.Monad (forM, forM_, mapM, mfilter, replicateM, void)

import Data.Maybe (listToMaybe)
import Data.Time.Clock.POSIX (getPOSIXTime)

import qualified Crypto.Hash.SHA512 as SHA512

import Data.ByteString (ByteString)
import qualified Data.ByteString
import qualified Data.ByteString.UTF8 as BSU

import System.Random (randomRIO)

data UserEntry = UserEntry
    { userId :: String
    , passwordHash :: ByteString
    , salt :: ByteString
    }

data IdUserEntry = IdUserEntry
    { _id :: String
    , userId :: String
    , passwordHash :: ByteString
    , salt :: ByteString
    }

data Token = Token
    { tokenValue :: String
    , userId :: String
    , expires :: Int
    }

data IdToken = IdToken
    { _id :: String
    , tokenValue :: String
    , userId :: String
    , expires :: Integer
    }

maxTokenAgeSec = 24 * 60 * 60

type MongoConnection = (forall a. Action IO a -> IO a)

login :: MongoConnection -> String -> String -> IO (Maybe String)
login connection userId password = do
    user <- getUser connection userId
    let matching = mfilter (comparePassword password) user
    forM matching (createToken connection)

challenge :: MongoConnection -> String -> IO (Maybe String)
challenge connection tokenValue = do
    time <- getPOSIXTime
    let timestamp :: Integer = floor time
    results <- connection $ next =<< find (select ["tokenValue" =: tokenValue] "tokens")
    let tokenValue :: Maybe String = do
            document <- results
            nonExpired <- mfilter (> timestamp) $ lookup "expires" document
            return $ lookup "tokenValue" document
    let update :: Action IO () = modify (select ["tokenValue" =: tokenValue] "tokens") ["expires" =: time + maxTokenAgeSec]
    forM_ tokenValue $ const $ connection update

    undefined

getUser :: MongoConnection -> String -> IO (Maybe UserEntry)
getUser connection userId = do
    results <- connection $ next =<< find (select ["userId" =: userId] "users")
    return $ do
        document <- results
        passwordHash <- unwrapBinary <$> lookup "passwordHash" document
        salt <- unwrapBinary <$> lookup "salt" document
        return $ UserEntry userId passwordHash salt

createToken :: MongoConnection -> UserEntry -> IO String
createToken connection user = do
    tokenValue <- createTokenValue
    time <- getPOSIXTime
    let timestamp = floor time
    let token =
            [ "tokenValue" =: tokenValue
            , "userId" =: user.userId
            , "expires" =: time + maxTokenAgeSec
            ]
    fmap (const tokenValue) $ connection $ save "tokens" token

createTokenValue :: IO String
createTokenValue = replicateM 30 $ randomRIO ('a', 'z')

unwrapBinary :: Binary -> ByteString
unwrapBinary (Binary bs) = bs

comparePassword :: String -> UserEntry -> Bool
comparePassword provided user =
    providedHash == user.passwordHash
  where
    providedHash = hashPassword providedBytes user.salt
    providedBytes = BSU.fromString provided

hashPassword :: ByteString -> ByteString -> ByteString
hashPassword password salt = SHA512.finalize ctx
  where
    ctx = foldl SHA512.update ctx0 [password, salt]
    ctx0 = SHA512.init
