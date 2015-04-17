{-# LANGUAGE ViewPatterns #-}
module Main where

import Control.Monad
import GEC.Datagram.Pure
import System.Entropy
import System.Exit
import Data.Maybe (isJust)

main :: IO ()
main = do
    testSmall
    -- XXX testLarge

testSmall :: IO ()
testSmall = do
    keyMat <- getEntropy 24
    let Just ctxIn  = mkContextIn Small keyMat
        Just ctxOut = mkContextOut Small keyMat
    msg <- getEntropy 32
    let Just (o1, e1)            = encode ctxOut msg
        Just (o2, e2)            = encode o1 msg
        Just (o3, e3)            = encode o2 msg
        Just (_ , e4)            = encode o3 msg
        Just (i1, (==msg) -> d1) = decode ctxIn e1
        Just (i2, (==msg) -> d2) = decode i1 e2
        Just (i3, (==msg) -> d3) = decode i2 e3
        Just (_ , (==msg) -> d4) = decode i3 e4
        Just (_ , (==msg) -> dX) = decode ctxIn e4
        f1 = decode i1 e1
        f2 = decode i2 e1
        f3 = decode i3 e1
        f4 = decode i2 e2
        f5 = decode i3 e2
        f6 = decode i3 e3
    when (any not [d1,d2,d3,d4,dX]) exitFailure
    when (any isJust [f1,f2,f3,f4,f5,f6]) exitFailure
