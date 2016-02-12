module GEC.KeyExchange
    ( -- * Types
      P.StsCtx, P.GecKeError(..), P.GenError, P.mkCtx
      -- * Aliases
    , P.Message1, P.Message2, P.Message3, P.KeyMaterial
      -- * Message Construction
    , initiate, respond, responseAck, finish
      -- * Constants
    , P.messageOneSize, P.messageTwoSize, P.messageThreeSize
    ) where

import qualified GEC.KeyExchange.Pure as P
import           Crypto.Random (CryptoRandomGen, throwLeft)

initiate :: CryptoRandomGen g => g -> P.StsCtx -> (P.Message1, P.StsCtx, g)
initiate g c = throwLeft (P.initiate g c)

respond :: CryptoRandomGen g => g -> P.StsCtx -> P.Message1 -> (P.Message1, P.StsCtx, g)
respond g c _m = throwLeft (P.initiate g c)

responseAck :: P.StsCtx -> P.Message2 -> Int -> (P.Message3, P.KeyMaterial)
responseAck c m n = throwLeft (P.responseAck c m n)

finish :: P.StsCtx -> P.Message3 -> Int -> P.KeyMaterial
finish c m n = throwLeft (P.finish c m n)
