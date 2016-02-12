{-# LANGUAGE BangPatterns    #-}
{-# LANGUAGE RecordWildCards #-}
module GEC.Datagram.Pure
           ( ContextIn, ContextOut, TagSize(..)
           , mkContextIn , mkContextOut
           , inflationOut, inflationIn
           , encode, decode
           ) where

import           Crypto.Cipher.AES128
import           Crypto.Classes ()
import           Crypto.Util

import           Control.Monad (guard)
import           Data.Word
import           Data.Bits
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B

data ContextIn =
        CtxIn { keyIn     :: GCMCtx AESKey128
              , window    :: {-# UNPACK #-} !SequenceWindow
              , saltIn    :: !ByteString -- 4 bytes
              , tagLenIn  :: {-# UNPACK #-} !Int
              }

data ContextOut =
       CtxOut { keyOut    :: GCMCtx AESKey128
              , count     :: {-# UNPACK #-} !Word32
              , saltOut   :: !ByteString -- 4 bytes
              , tagLenOut :: {-# UNPACK #-} !Int
              }

data TagSize = Small | Full

-- Translate the ADT to a byte size
tagSize :: TagSize -> Int
tagSize Small = 12
tagSize Full  = 16

countLength :: Int
countLength = 4

inflationOut :: ContextOut -> Int
inflationOut (CtxOut {..}) = tagLenOut + countLength

inflationIn :: ContextIn -> Int
inflationIn (CtxIn {..}) = tagLenIn  + countLength

mkContextOut :: TagSize -> ByteString -> Maybe ContextOut
mkContextOut sz material = do
        guard (B.length material >= 24)
        gctx <- makeGCMCtx key
        return $ CtxOut gctx cnt salt tagLen
  where
      (key,salt) = B.splitAt 16 material
      cnt    = 1
      tagLen = tagSize sz

mkContextIn  :: TagSize -> ByteString -> Maybe ContextIn
mkContextIn sz material =
    do guard (B.length material >= 24)
       gctx <- makeGCMCtx key
       return $ CtxIn gctx win salt tagLen
  where
      (key,salt) = B.splitAt 16 material
      win        = SW 1 0
      tagLen     = tagSize sz

encode :: ContextOut -> ByteString -> Maybe (ContextOut, ByteString)
encode ctx@(CtxOut {..}) msg =
      if count == maxBound
        then Nothing
        else let res = ( ctx { count = count + 1 }
                       , cnt ## ciphertext ## tag )
             in res `seq` Just res
  where
    tag = B.take tagLenOut (unAuthTag fullTag)
    aad = B.empty
    cnt = p32 count
    iv  = cnt ## saltOut
    (ciphertext,fullTag) = encryptGCM keyOut iv msg aad

decode :: ContextIn -> ByteString -> Maybe (ContextIn, ByteString)
decode ctx@(CtxIn { .. }) msg
    | Just sw <- newWindow =
        if constTimeEq authTagRecv (B.take tagLenIn $ unAuthTag authTagCompute)
            then Just ( ctx { window = sw }, plaintext)
            else Nothing
    | otherwise = Nothing
  where
    aad = B.empty
    iv  = cnt ## saltIn
    newWindow               = nextWindow window (c32 cnt)
    (firstPart,authTagRecv) = B.splitAt (B.length msg - tagLenIn) msg
    (cnt,ciphertext)        = B.splitAt countLength firstPart
    (plaintext, authTagCompute) = decryptGCM keyIn iv ciphertext aad

p32 :: Word32 -> ByteString
p32 w = B.pack [ fromIntegral $ w `shiftR` 24
               , fromIntegral $ w `shiftR` 16
               , fromIntegral $ w `shiftR` 8
               , fromIntegral $ w `shiftR` 0
               ]

c32 :: ByteString -> Word32
c32 x | B.length x == 4 = let [a,b,c,d] = B.unpack x
                          in fromIntegral a `shiftL` 24 +
                             fromIntegral b `shiftL` 16 +
                             fromIntegral c `shiftL` 8 +
                             fromIntegral d `shiftL` 0
      | otherwise = maxBound

data SequenceWindow =
        SW { swBase :: !Word32
           , swMask :: !Word32
           }

nextWindow :: SequenceWindow -> Word32 -> Maybe SequenceWindow
nextWindow ctx c
    | c < swBase ctx                                       = Nothing
    | testBit (swMask ctx) (fromIntegral $ c - swBase ctx) = Nothing
    | otherwise = let new = go ctx
                  in Just new { swMask = setBit (swMask new) (fromIntegral $ c - swBase new) }
  where
    go sw@(SW b m) | odd m     = go (SW  (b + 1) (m `shiftR` 1))
                   | otherwise = sw

(##) :: ByteString -> ByteString -> ByteString
(##) = B.append
