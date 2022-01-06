
module Users (
    login,
    challenge,
    maxTokenAgeSec
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

import qualified Mongo

data UserEntry = UserEntry
    { userId :: String
    , passwordHash :: ByteString
    , salt :: ByteString
    } deriving (Eq, Show)

maxTokenAgeSec = 24 * 60 * 60

tokensCollection = "tokens"
usersCollection = "users"

userIdField = "userId"
passwordHashField = "passwordHash"
saltField = "salt"

tokenValueField = "tokenValueField"
expiresField = "expires"

login :: Mongo.Execution -> String -> String -> IO (Maybe String)
login connection userId password = do
    user <- getUser connection userId
    _ <- print user
    let matching = mfilter (comparePassword password) user
    forM matching (createToken connection)

challenge :: Mongo.Execution -> String -> IO (Maybe String)
challenge connection tokenValue = do
    time <- getPOSIXTime
    let timestamp :: Integer = floor time
    results <- connection $ next =<< find (select [tokenValueField =: tokenValue] tokensCollection)
    let tokenValue = do
            document <- results
            nonExpired <- mfilter (> timestamp) $ lookup expiresField document
            return $ lookup tokenValueField document
    let update = modify
                (select [tokenValueField =: tokenValue] tokensCollection)
                ["$set" =: [expiresField =: time + maxTokenAgeSec]]
    forM_ tokenValue $ const $ connection update
    return tokenValue

getUser :: Mongo.Execution -> String -> IO (Maybe UserEntry)
getUser connection userId = do
    results <- connection $ next =<< find (select [userIdField =: userId] usersCollection)
    return $ do
        document <- results
        passwordHash <- unwrapBinary <$> lookup passwordHashField document
        salt <- unwrapBinary <$> lookup saltField document
        return $ UserEntry userId passwordHash salt

createToken :: Mongo.Execution -> UserEntry -> IO String
createToken connection user = do
    tokenValue <- createTokenValue
    time <- getPOSIXTime
    let timestamp = floor time
    let token =
            [ tokenValueField =: tokenValue
            , userIdField =: user.userId
            , expiresField =: time + maxTokenAgeSec
            ]
    fmap (const tokenValue) $ connection $ save tokensCollection token

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
