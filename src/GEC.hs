{-# LANGUAGE BangPatterns    #-}
{-# LANGUAGE RecordWildCards #-}
module GEC ( ContextIn, ContextOut, TagSize(..)
           , mkInContext , mkOutContext
           , inflationOut, inflationIn 
           , encode, decode
           ) where

import Crypto.Cipher.AES128
import Crypto.Classes (IV(..), ctr)
import Crypto.Util
import Data.Word
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

data ContextIn =
        CtxIn { keyIn     :: GCMCtx AESKey128
              , window    :: {-# UNPACK #-} !SequenceWindow
              , saltIn    :: !ByteString -- 4 bytes
              , tagLenIn  :: {-# UNPACK #-} !Int
              }

data ContextOut =
       CtxOut { keyOut    :: GCMCtx AESKey128
              , count     :: {-# UNPACK #-} !Word64
              , saltOut   :: !ByteString -- 4 bytes
              , tagLenOut :: {-# UNPACK #-} !Int
              }

data TagSize = Small | Full

countLength :: Int
countLength = 8

inflationOut :: ContextOut -> Int
inflationOut (CtxOut {..}) = tagLenOut + countLength

inflationIn :: ContextIn -> Int
inflationIn (CtxIn {..}) = tagLenIn  + countLength

mkOutContext :: TagSize -> ByteString -> Maybe ContextOut
mkOutContext sz material = do
        gctx <- makeGCMCtx key
        return $ CtxOut gctx cnt salt tagLen
  where
      (key,salt) = B.splitAt 16 material
      cnt    = case sz of
                   Small -> maxBound - (2^32)
                   Full  -> 0
      tagLen = case sz of
                   Small -> 8
                   Full  -> 16

mkInContext  :: TagSize -> ByteString -> Maybe ContextIn
mkInContext sz material
    | Just gctx <- makeGCMCtx key = Just $ CtxIn gctx win salt tagLen
    | otherwise                   = Nothing
  where
      (key,salt) = B.splitAt 16 material
      win    = case sz of
                   Small -> SW (maxBound - (2^32)) 0
                   Full  -> SW 0 0
      tagLen = case sz of
                   Small -> 8
                   Full  -> 16

encode :: ContextOut -> ByteString -> Maybe (ContextOut, ByteString)
encode ctx@(CtxOut {..}) msg
    | tagLenOut < 16 && count >= 2^32 = Nothing
    | count >= 2^48                   = Nothing
    | otherwise                       =
      if count == maxBound
        then Nothing
        else let res = ( ctx { count = count + 1 }
                       , cnt ## ciphertext ## tag )
             in res `seq` Just res
  where
    tag = B.take tagLenOut (unAuthTag fullTag)
    aad = B.empty
    cnt = p64 count
    iv  = cnt ## saltOut
    (ciphertext,fullTag) = encryptGCM keyOut iv msg aad

decode :: ContextIn -> ByteString -> Maybe (ContextIn, ByteString)
decode ctx@(CtxIn { .. }) msg
    | Just sw <- newWindow =
        if constTimeEq authTagRecv (unAuthTag authTagCompute)
            then Just ( ctx { window = sw }, plaintext)
            else Nothing
    | otherwise = Nothing
  where
    aad = B.empty
    iv  = cnt ## saltIn
    newWindow               = nextWindow window (c64 cnt)
    (firstPart,authTagRecv) = B.splitAt (B.length msg - tagLenIn) msg
    (cnt,ciphertext)        = B.splitAt countLength firstPart
    (plaintext, authTagCompute) = decryptGCM keyIn iv ciphertext aad

p64 :: Word64 -> ByteString
p64 w = B.pack [ fromIntegral $ w `shiftR` 56
               , fromIntegral $ w `shiftR` 48
               , fromIntegral $ w `shiftR` 40
               , fromIntegral $ w `shiftR` 32
               , fromIntegral $ w `shiftR` 24
               , fromIntegral $ w `shiftR` 16
               , fromIntegral $ w `shiftR` 8
               , fromIntegral $ w `shiftR` 0
               ]

c64 :: ByteString -> Word64
c64 x | B.length x == 8 = let [a,b,c,d,e,f,g,h] = B.unpack x
                          in fromIntegral a `shiftL` 56 +
                             fromIntegral b `shiftL` 48 +
                             fromIntegral c `shiftL` 40 +
                             fromIntegral d `shiftL` 32 +
                             fromIntegral e `shiftL` 24 +
                             fromIntegral f `shiftL` 16 +
                             fromIntegral g `shiftL` 8 +
                             fromIntegral h `shiftL` 0
      | otherwise       = maxBound

data SequenceWindow =
        SW { swBase :: !Word64
           , swMask :: !Word64
           }

nextWindow :: SequenceWindow -> Word64 -> Maybe SequenceWindow
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
