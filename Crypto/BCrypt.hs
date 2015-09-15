{-# LANGUAGE ForeignFunctionInterface #-}
{- | A module for hashing passwords with bcrypt.

     >>> import Crypto.BCrypt
     >>> let p = Data.ByteString.Char8.pack
     >>> hashPasswordUsingPolicy slowerBcryptHashingPolicy (p "mypassword")
     Just "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6"
     >>> validatePassword (p "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6") (p "badpass")
     False
     >>> validatePassword (p "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6") (p "mypassword")
     True
     >>> hashUsesPolicy slowerBcryptHashingPolicy (p "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6")
     True
     >>> hashUsesPolicy fastBcryptHashingPolicy (p "$2y$14$xBBZdWgTa8fSU1aPFP5IxeVdUKfT7hUDjmusZEAiNBiYaYEGY/Sh6")
     False
 -}
module Crypto.BCrypt (HashingPolicy(..), hashPasswordUsingPolicy, validatePassword,
                      fastBcryptHashingPolicy, slowerBcryptHashingPolicy,
                      hashUsesPolicy, hashPassword, genSalt, genSaltUsingPolicy)
where

import Foreign
import Foreign.C.String
import Foreign.C.Types
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Unsafe as BS
import qualified System.IO.Unsafe as U
import Control.Monad
import Data.ByteArray (constEq)
import System.Entropy

foreign import ccall "crypt_ra" c_crypt_ra :: CString -> CString -> Ptr CString -> Ptr CInt -> IO CString
foreign import ccall "crypt_gensalt_ra" c_crypt_gensalt_ra :: CString -> CULong -> CString -> CInt -> IO CString

-- | A hashing policy defines the type of password hashing to use.
data HashingPolicy = HashingPolicy {
    -- | Preferred cost - how strong new passwords should be. This is a trade-off
    --   between making hasing / checking passwords faster in your system, and making
    --   brute forcing passwords harder for an adversary.
    --   The intention is that this can be increased as computers get faster.
    --   To give a rough indication of the scale of preferredCost,
    --     on a 2.6 GHz AMD Athlon machine (64 bit kernel), using a single core:
    --
    --       * Cost 4: 139 passwords / second
    --
    --       * Cost 5: 85 passwords / second
    --
    --       * Cost 6: 44 passwords / second
    --
    --       * Cost 7: 23 passwords / second
    --
    --       * Cost 8: 11 passwords / second
    --
    --       * Cost 9: 5.7 passwords / second
    --
    --       * Cost 10: 2.8 passwords / second
    --
    --       * Cost 11: 1.4 passwords / second
    --
    --       * Cost 12: 0.72 passwords / second
    preferredHashCost :: Int,
    -- | Preferred algorithm - the preferred hash algorithm.
    --   The default is $2y$ (compatible with other Openwall-based
    --   libraries). The most up-to-date version is $2b$.
    preferredHashAlgorithm :: BS.ByteString
  }

-- | Hashes a password, using a hashing policy.
hashPasswordUsingPolicy :: HashingPolicy -> BS.ByteString -> IO (Maybe BS.ByteString)
hashPasswordUsingPolicy hp pw = do
  ms <- genSaltUsingPolicy hp
  return $ do
    s <- ms
    hashPassword pw s

-- | Validates a password. The first argument is the hashed password, the second is
--   the password attempt.
--   Note: If a password validates successfully, it is a good idea to check if the
--   password is up to the current policy using hashUsesPolicy, and re-hashing it
--   if not.
validatePassword :: BS.ByteString -> BS.ByteString -> Bool
validatePassword h pw =
  case hashPassword pw h
    of
      Nothing -> False
      Just h2 -> h2 `constEq` h

-- | A policy that allows passwords to be hashed reasonably quickly, but for that
--   reason isn't suitable for high security applications.
fastBcryptHashingPolicy :: HashingPolicy
fastBcryptHashingPolicy = HashingPolicy 4 (BS.pack "$2y$")

-- | A policy which makes password hashing substantially slower than
--   fastBcryptHashingPolicy, and so makes it more difficult for an adversary to
--   decrypt passwords. In a high security environment, this policy should be
--   regularly reviewed against hardware developments.
slowerBcryptHashingPolicy :: HashingPolicy
slowerBcryptHashingPolicy = fastBcryptHashingPolicy { preferredHashCost = 14 }

-- | Check whether a password hash is consistent with the current policy, or if
--   it should be updated.
hashUsesPolicy :: HashingPolicy -> BS.ByteString -> Bool
hashUsesPolicy (HashingPolicy phc pha) str =
  let phaLen = BS.length pha
      strPref = BS.take phaLen str
      strInfo = BS.take 2 (BS.drop phaLen str)
      hcBase = if phc < 10 then '0':(show phc) else show phc
  in
   (strPref == pha) && (hcBase == BS.unpack strInfo)

-- | Hashes a password (first argument) using the settings specified in second
--   argument. The settings describe the hashing variant and salt to use; because
--   the settings are prepended to password hashes, passing in an existing password
--   hash will cause the same settings to be used again.
--   You can create a hash using genSalt.
--   Result: Just hash on success, Nothing on failure (invalid settings).
hashPassword :: BS.ByteString -> BS.ByteString -> Maybe BS.ByteString
hashPassword pw setting =
  U.unsafePerformIO $ BS.useAsCString pw $
    \pw' -> BS.useAsCString setting $
      \setting' -> alloca $ \data' -> alloca $ \dlen -> do
        poke dlen 0
        poke data' nullPtr
        res <- c_crypt_ra pw' setting' data' dlen
        newData <- peek data'
        if newData == nullPtr
          then
              return Nothing
          else
            do
              ret <- if res == nullPtr
                       then
                         return Nothing
                       else
                         liftM Just $ BS.packCString res
              free newData
              return ret

-- | Prepares a settings string and salt suitable for use with hashPassword.
--   Takes a prefix specifying the type of hash, an integer specifying the
--   computational cost of hashing (4-32, or 0 for a low default), and a
--   string of random entropy.
genSalt :: BS.ByteString -> Int -> BS.ByteString -> Maybe BS.ByteString
genSalt settings cost entropy =
  U.unsafePerformIO $ BS.useAsCString settings $ \settings' ->
    BS.unsafeUseAsCString entropy $ \entropy' -> do
      res <- c_crypt_gensalt_ra settings' (fromIntegral cost) entropy' (fromIntegral $ BS.length entropy)
      if res == nullPtr
        then
          return Nothing
        else
          do
            ret <- BS.packCString res
            free res
            return $ Just ret

-- | Generates a salt using a policy, sampling from a system-appropriate source.
genSaltUsingPolicy :: HashingPolicy -> IO (Maybe BS.ByteString)
genSaltUsingPolicy (HashingPolicy hc ha) = do
  ent <- getEntropy 16
  return $ genSalt ha hc ent
