{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE ParallelListComp #-}
module Main where

import qualified Data.ByteString as B
import Crypto.Classes (zwp')
import Control.Monad
import Control.Monad.CryptoRandom
import Control.Monad.Trans.Except
import Crypto.Ed25519 as Ed
import Crypto.Random
import GEC.KeyExchange.Pure
import System.Exit (exitFailure)

main :: IO ()
main = do
    trueTests  <- sequence $ map runTest [succ1]
    falseTests <- sequence $ map runTest [fail1, fail2, fail3, fail4]
    when (any failed   trueTests)  exitFailure
    when (any success falseTests) exitFailure

failed :: Either e Bool -> Bool
failed = either (const True) not

success :: Either e Bool -> Bool
success = either (const False) id

type TestFunction = StsCtx -> StsCtx -> StsCtx -> SystemRandom -> SystemRandom -> Except GecKeError Bool

runTest :: TestFunction -> IO (Either GecKeError Bool)
runTest f = do
    gA              <- newGenIO :: IO SystemRandom
    gB              <- newGenIO :: IO SystemRandom
    (q1,p1)         <- keyPairIO
    (q2,p2)         <- keyPairIO
    (qWrong,pWrong) <- keyPairIO
    let stsA = mkCtx (p1,q1) p2
        stsB = mkCtx (p2,q2) p1
        stsC = mkCtx (pWrong,qWrong) p2
    return $ runExcept (f stsA stsB stsC gA gB)

--------------------------------------------------------------------------------
--  Framework Done: beginning of test functions

succ1 :: TestFunction
succ1 sts1_A sts1_B _ gA gB =
   do (msg1,sts2_A,_) <- except $ initiate gA sts1_A
      (msg2,sts2_B,_) <- except $ respond gB sts1_B msg1
      (msg3,km_A)     <- except $ responseAck sts2_A msg2 kmSize
      km_B            <- except $ finish sts2_B msg3 kmSize
      return (km_A == km_B)
  where kmSize = 128

-- Fail when the context is for the wrong party
fail1 :: TestFunction
fail1 sts1_A _ sts1_B gA gB =
       do (msg1,sts2_A,_) <- except $ initiate gA sts1_A
          (msg2,sts2_B,_) <- except $ respond gB sts1_B msg1
          (msg3,km_A)     <- except $ responseAck sts2_A msg2 kmSize
          km_B            <- except $ finish sts2_B msg3 kmSize
          return (km_A == km_B)
  where kmSize = 128

-- Fail when message 1 is munged
fail2 :: TestFunction
fail2 sts1_A _ sts1_B gA gB =
       do (msg1,sts2_A,r) <- except $ initiate gA sts1_A
          (msg2,sts2_B,_) <- except $ respond gB sts1_B (corrupt r msg1)
          (msg3,km_A)     <- except $ responseAck sts2_A msg2 kmSize
          km_B            <- except $ finish sts2_B msg3 kmSize
          return (km_A == km_B)
  where kmSize = 128

-- Fail when message 2 is munged
fail3 :: TestFunction
fail3 sts1_A _ sts1_B gA gB =
       do (msg1,sts2_A,r) <- except $ initiate gA sts1_A
          (corrupt r -> msg2,sts2_B,_) <- except $ respond gB sts1_B msg1
          (msg3,km_A)     <- except $ responseAck sts2_A msg2 kmSize
          km_B            <- except $ finish sts2_B msg3 kmSize
          return (km_A == km_B)
  where kmSize = 128

-- Fail when message 3 is munged
fail4 :: TestFunction
fail4 sts1_A _ sts1_B gA gB =
       do (msg1,sts2_A,r) <- except $ initiate gA sts1_A
          (msg2,sts2_B,_) <- except $ respond gB sts1_B msg1
          (corrupt r -> msg3,km_A)     <- except $ responseAck sts2_A msg2 kmSize
          km_B            <- except $ finish sts2_B msg3 kmSize
          return (km_A == km_B)
  where kmSize = 128

--------------------------------------------------------------------------------
--  Utils

keyPairIO :: IO (Ed.PrivateKey,Ed.PublicKey)
keyPairIO = do
    g <- newGenIO :: IO SystemRandom
    let (q,p,_) = Ed.generateKeyPair g
    return (q,p)

corrupt :: SystemRandom -> B.ByteString -> B.ByteString
corrupt gen bs = fst $ throwLeft $ runCRand go gen
 where
  len = B.length bs
  go :: CRand SystemRandom GenError B.ByteString
  go  = do
    nr   <- getCRandomR (1,len-1)
    idxs <- replicateM nr (getCRandomR (0,len-1))
    rs   <- replicateM nr (getCRandomR (1,maxBound))
    let off = map B.pack [ replicate idx 0 ++ [r] ++ replicate (len-idx-1) 0 | idx <- idxs | r <- rs]
        res = foldr zwp' bs off
    if res == bs then go else return res
