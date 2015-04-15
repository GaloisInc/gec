{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE DeriveDataTypeable #-}
module GEC.KeyExchange.Pure
    (
    -- * Types
      StsCtx, GecKeError(..), GenError(..), StsResult
    -- * Aliases
    , Message1, Message2, Message3, KeyMaterial
    -- * Message construction
    , initiate
    , respond
    , responseAck
    , finish
    -- * Helper information
    , messageOneSize, messageTwoSize, messageThreeSize
    ) where

import           Crypto.Random (GenError, CryptoRandomGen)
import           Crypto.Classes (ctr, buildKey, IV(..))
import           Crypto.Cipher.AES128 (AESKey128)
import           Crypto.Curve25519.Pure         as Curve
import           Crypto.Ed25519.Pure            as Ed
import qualified Crypto.Hash.SHA512             as SHA

import           Control.Exception
import           Control.Monad.Except
import           Control.Monad.Trans.Except (except)
import           Data.ByteString (ByteString)
import qualified Data.ByteString                as B
import           Data.Bits
import           Data.Data

--------------------------------------------------------------------------------
--  Constants

messageOneSize, messageTwoSize, messageThreeSize :: Int
messageOneSize   = pubKeySize
messageTwoSize   = pubKeySize + sigSize + pubKeySize + pubKeySize
messageThreeSize = sigSize + pubKeySize + pubKeySize

pubKeySize, sigSize :: Int
pubKeySize = 32
sigSize    = 64

-- Key encryption key material length (128 bit aes key + 64 bit salt)
kckLen :: Int
kckLen = 24

--------------------------------------------------------------------------------
--  Types

data StsCtx = STS0
                { meP        :: Ed.PublicKey
                , meQ        :: Ed.PrivateKey
                , themP      :: Ed.PublicKey
                }
            | Init1
                { meP        :: Ed.PublicKey
                , meQ        :: Ed.PrivateKey
                , themP      :: Ed.PublicKey
                , ephemP     :: Curve.PublicKey
                , ephemQ     :: Curve.PrivateKey
                }

            | Resp1
                { meP          :: Ed.PublicKey
                , meQ          :: Ed.PrivateKey
                , themP        :: Ed.PublicKey
                , ephemP       :: Curve.PublicKey
                , ephemQ       :: Curve.PrivateKey
                , themEphemP   :: Curve.PublicKey
                , theirKCK     :: ByteString -> ByteString
                , sharedSecret :: ByteString
                }

data GecKeError = GeneratorError GenError
                | InvalidInput
                | InvalidContext
                deriving (Eq, Ord, Show, Read, Data, Typeable)

instance Exception GecKeError

data Party = Initiator | Responder | Client
        deriving (Enum)

type StsResult a = Either GecKeError a

type Message1 = ByteString
type Message2 = ByteString
type Message3 = ByteString
type KeyMaterial = ByteString

--------------------------------------------------------------------------------
--  Message Construction

initiate    :: CryptoRandomGen g => g -> StsCtx -> StsResult (Message1,StsCtx,g)
initiate g (STS0 { .. }) = runExcept $ do
    (ephemQ,ephemP,g2) <- genKeyPair g
    return (Curve.exportPublic ephemP, Init1 { .. } , g2)

respond    :: CryptoRandomGen g => g -> StsCtx -> Message1 -> StsResult (Message2,StsCtx,g)
respond g (STS0 {..}) msg
  | Just themEphemP <- Curve.importPublic msg = runExcept $ do
    (ephemQ,ephemP,g2) <- genKeyPair g
    let sharedSecret = makeShared ephemQ themEphemP
        myKCK        = e_kck $ kdf kckLen Responder sharedSecret
        theirKCK     = e_kck $ kdf kckLen Initiator sharedSecret
        signData     = Curve.exportPublic ephemP ## Curve.exportPublic themEphemP
        Sig sig      = Ed.sign signData meQ meP
        encOf_sig_ephemP_themEphemP = myKCK (sig ## signData)
    return ( Curve.exportPublic ephemP ## encOf_sig_ephemP_themEphemP
           , Resp1 { .. }
           , g2)
  | Nothing <- Curve.importPublic msg = Left InvalidInput
respond _ _ _ = Left InvalidContext

responseAck :: StsCtx -> Message2 -> Int -> StsResult (Message3, KeyMaterial)
responseAck (Init1 {..}) msg nrBytes
  | B.length msg /= messageTwoSize = Left InvalidInput
  | otherwise =
      if Ed.valid signedData themP (Sig sig) && ephemP' == Curve.exportPublic ephemP && themEphemP' == themEphemP
          then return (responseMsg, keyMaterial)
          else Left InvalidInput
  where
   -- Parse the incoming message and derive key material
   (themEphemP,encData)  = B.splitAt pubKeySize msg
   decryptedData         = theirKCK encData
   (sig,signedData)      = B.splitAt sigSize decryptedData
   (themEphemP',ephemP') = B.splitAt pubKeySize signedData
   sharedSecret          = makeShared ephemQ (myJust $ Curve.importPublic themEphemP)
   theirKCK              = e_kck $ kdf kckLen Responder sharedSecret
   myKCK                 = e_kck $ kdf kckLen Initiator sharedSecret
   -- Now construct the response message
   unsignedOutput = Curve.exportPublic ephemP ## themEphemP
   (Sig outSig)   = Ed.sign unsignedOutput meQ meP
   signedOut      = outSig ## unsignedOutput
   responseMsg    = myKCK signedOut
   -- Derive the client's key material
   keyMaterial = kdf nrBytes Client sharedSecret
   myJust (Just x) = x
   myJust _        = error "Impossible: The Message2 bytestring is of proper length but pub key too small!"
responseAck _ _ _ = Left InvalidContext

finish      :: StsCtx -> Message3 -> Int -> StsResult KeyMaterial
finish (Resp1 {..}) msg nrBytes
  | B.length msg /= messageThreeSize            = Left InvalidInput
  | Ed.valid signedData themP (Sig sig) &&
    ephemP' == Curve.exportPublic ephemP &&
    themEphemP' == Curve.exportPublic themEphemP = return keyMaterial
  | otherwise                                   = Left InvalidInput
  where
    decryptedData         = theirKCK msg
    (sig,signedData)      = B.splitAt sigSize decryptedData
    (themEphemP',ephemP') = B.splitAt pubKeySize signedData
    keyMaterial           = kdf nrBytes Client sharedSecret
finish _ _ _ = Left InvalidContext


--------------------------------------------------------------------------------
--  Utils

-- @kdf nrBytes p secret@ will derive a secret of byte length @nrBytes@
-- using additional data @p@ and shared secret @secret@.
--
-- The KDF algorithm is an iterated SHA512:
--
-- @
--    H( 0 || secret || PARTY ) || H( 1 || secret || PARTY ) || H ( 2  || secret || PARTY)
-- @
--
-- Where the counter (0,1..) is a 16 bit big endian number, secret is the
-- shared secret of 32 bytes, and PARTY is one byte (0 for Initiator, 1 for
-- Responder, 2 for Client key material).
kdf :: Int -> Party -> ByteString -> ByteString
kdf nrBytes p sec
    | nrBytes > (2^16 * 64) = error "Will not derive over 2^16 * 64 bytes from the secret key material with ~128 bits.  If you wrote the code to do this intentionally then you should hire someone to write this bit of code for you - you're using it wrong!"
    | otherwise = B.take nrBytes full
 where
     full  = B.concat $ map sha512 [B.concat [p16 cnt, sec, party] | cnt <- [0..nrBlk-1]]
     party = encodeParty p
     p16 c = B.pack [fromIntegral $ (c `shiftR` 8) .&. 0xFF , fromIntegral $ c .&. 0xFF]
     nrBlk = (nrBytes + blkSz - 1) `div` blkSz
     blkSz = 512 `div` 8



-- Encryption/decryption function that consume key material of kckLen and
-- produces a stream cipher.
e_kck :: ByteString -> (ByteString -> ByteString)
e_kck mat =
    let (key,salt) = B.splitAt 16 mat
        Just k     = buildKey key :: Maybe AESKey128
        iv         = IV (salt ## B.replicate 8 0)
    in fst . ctr k iv

encodeParty :: Party -> ByteString
encodeParty = B.pack . (:[]) . fromIntegral . fromEnum

(##) :: ByteString -> ByteString -> ByteString
(##) = B.append

sha512 :: ByteString -> ByteString
sha512 = SHA.hash

genKeyPair :: CryptoRandomGen g => g -> Except GecKeError (Curve.PrivateKey, Curve.PublicKey, g)
genKeyPair = except . either (Left . GeneratorError) Right . Curve.generateKeyPair

