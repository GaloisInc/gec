module GEC.Datagram
    ( P.ContextIn, P.ContextOut, P.TagSize(..)
    , mkContextIn, mkContextOut
    , P.inflationOut, P.inflationIn
    , encode, decode
    ) where

import qualified GEC.Datagram.Pure as P
import Data.ByteString (ByteString)

mkContextIn :: P.TagSize -> ByteString -> P.ContextIn
mkContextIn t m = run "Could not construct input context" (P.mkContextIn t m)

mkContextOut :: P.TagSize -> ByteString -> P.ContextOut
mkContextOut t m = run "Could not construct output context" (P.mkContextOut t m)

encode :: P.ContextOut -> ByteString -> (P.ContextOut, ByteString)
encode c m = run "Could not encode message" (P.encode c m)

decode :: P.ContextIn -> ByteString -> (P.ContextIn, ByteString)
decode c m = run "Could not decode message" (P.decode c m)

run :: String -> Maybe a -> a
run msg = maybe (error $ "GEC: " ++ msg) id
