{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Focused unit tests for the fork-mode header-issuer check
-- ('Ouroboros.Consensus.Protocol.Praos.validateIssuerIsLocalPool').
--
-- The local pool id is read once from @CARDANO_FORK_POOL_ID@ at module load, so
-- each case is run in a child process (spawned by the parent) with a
-- purpose-built environment. 'validateIssuerIsLocalPool' takes the issuer cold
-- key hash directly (in the node it is @'hashKey' ('hvVK' b)@), so the test only
-- needs a single verification key, not a whole header.
module Main (main) where

import Cardano.Crypto.DSIGN (deriveVerKeyDSIGN, genKeyDSIGN)
import Cardano.Crypto.Hash (hashToBytes)
import Cardano.Crypto.Seed (mkSeedFromBytes)
import Cardano.Ledger.Hashes (KeyHash (unKeyHash), KeyRole (BlockIssuer))
import Cardano.Ledger.Keys (VKey (VKey), hashKey)
import Cardano.Protocol.Crypto (StandardCrypto)
import Control.Monad (unless)
import Control.Monad.Except (runExcept)
import qualified Data.ByteString as BS
import Data.Char (intToDigit)
import Ouroboros.Consensus.Protocol.Praos (
  PraosValidationErr (IssuerNotLocalPool),
  validateIssuerIsLocalPool,
 )
import Control.Exception (SomeException, evaluate, try)
import Data.List (isInfixOf)
import System.Environment (getArgs, getEnvironment, getExecutablePath)
import System.Exit (ExitCode (ExitSuccess), exitFailure, exitSuccess)
import System.IO (hPutStrLn, stderr)
import System.Process (env, proc, readCreateProcessWithExitCode)

-- | A deterministic block-issuer cold verification key.
sampleVKey :: VKey BlockIssuer
sampleVKey = VKey (deriveVerKeyDSIGN (genKeyDSIGN (mkSeedFromBytes (BS.replicate 32 7))))

-- | The 28-byte hash of 'sampleVKey' as it appears in @CARDANO_FORK_POOL_ID@.
issuerHashHex :: String
issuerHashHex = toHex (hashToBytes (unKeyHash (hashKey sampleVKey)))

-- | A different 28-byte hash.
otherHashHex :: String
otherHashHex = toHex (BS.replicate 28 0xEE)

toHex :: BS.ByteString -> String
toHex = concatMap byte . BS.unpack
  where
    byte w = [intToDigit (fromIntegral w `div` 16), intToDigit (fromIntegral w `mod` 16)]

-- | The issuer cold key hash the header validator would derive from the header
-- ('hashKey' of 'hvVK'), instantiated at 'StandardCrypto'.
issuerCheck :: Either (PraosValidationErr StandardCrypto) ()
issuerCheck = runExcept (validateIssuerIsLocalPool (hashKey sampleVKey))

check :: String -> Bool -> IO ()
check label cond = unless cond (die ("assertion failed: " ++ label))

die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitFailure

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["match"] ->
      check "issuer == local pool: accepted" $
        issuerCheck == Right ()
    ["mismatch"] ->
      check "issuer /= local pool: rejected with IssuerNotLocalPool" $
        case issuerCheck of
          Left (IssuerNotLocalPool _) -> True
          _ -> False
    ["unset"] -> do
      r <- try (evaluate issuerCheck)
      case r of
        Left (e :: SomeException) ->
          check "no pool id: loud failure names CARDANO_FORK_POOL_ID" $
            "CARDANO_FORK_POOL_ID" `isInfixOf` show e
        Right _ -> die "expected a loud failure when CARDANO_FORK_POOL_ID is unset"
    [] -> runParent
    _ -> die "usage: forkmode-issuer-test [match|mismatch|unset]"

runParent :: IO ()
runParent = do
  self <- getExecutablePath
  baseEnv <- filter (not . isForkVar . fst) <$> getEnvironment
  let scenarios =
        [ ("match", [("CARDANO_FORK_POOL_ID", issuerHashHex)])
        , ("mismatch", [("CARDANO_FORK_POOL_ID", otherHashHex)])
        , ("unset", [])
        ]
  results <- mapM (runScenario self baseEnv) scenarios
  if and results
    then do
      putStrLn "ouroboros-consensus fork-mode issuer check: all cases passed"
      exitSuccess
    else exitFailure
  where
    isForkVar name = take (length "CARDANO_FORK_") name == "CARDANO_FORK_"

runScenario :: String -> [(String, String)] -> (String, [(String, String)]) -> IO Bool
runScenario self baseEnv (name, extra) = do
  let cp = (proc self [name]) {env = Just (baseEnv ++ extra)}
  (code, out, err) <- readCreateProcessWithExitCode cp ""
  let ok = code == ExitSuccess
  putStrLn $ (if ok then "PASS " else "FAIL ") ++ name
  unless ok $ do
    unless (null out) (hPutStrLn stderr ("  stdout: " ++ out))
    unless (null err) (hPutStrLn stderr ("  stderr: " ++ err))
  pure ok
