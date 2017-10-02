module Main where

{-| Imports -}
import Options.Applicative hiding (many)
import Control.Applicative ((<*>), (<*), (*>))
import Control.Monad (when)
import Data.Semigroup ((<>))
import System.Exit (exitSuccess)
import System.Process (callCommand)
import Data.Char (digitToInt)

{-| Parsec Imports -}
import Text.Parsec 
           ( Parsec(..)
           , parse
           , spaces
           , char
           , letter
           , string
           , anyChar
           , try
           , oneOf
           , many
           )

import Text.Parsec.Combinator 
           ( manyTill
           , count
           )


{-| Options -}

data Options = Options
    { optTest        :: Bool
    , optInteractive :: Bool
    , optVerbose     :: Bool
    } 


{-| Type Aliases -}

type CurrentLine = Int
type Tries       = Int
type Choice      = Int


{-| Connection Attempts -}

data Attempt = Attempt 
    { getDate  :: Date
    , getTime  :: Time
    , getIP    :: IP 
    }

instance Show Attempt where
  show (Attempt date time ip) =
    (show ip) <> " " <> (show date) 
              <> " -- " <> (show time)


{-| Date and Time -}

data Date = Date
    { month :: String
    , day   :: Int
    }

instance Show Date where
  show date = (show $ month date) <> " "
           <> (show $ day date)

data Time = Time
    { hour   :: Int
    , minute :: Int
    , second :: Int
    }

instance Show Time where
  show time = (show $ hour time)   <> ":" <>
              (show $ minute time) <> ":" <>
              (show $ second time)


{-| IP -}

data IP = IP Int Int Int Int
    deriving Eq

instance Show IP where
  show (IP a b c d) = a' <> "." <> b' <> "."
                   <> c' <> "." <> d' <> (take n $ repeat ' ')
    where
      a' = show a
      b' = show b
      c' = show c
      d' = show d
      n  = 12 - (length a' + length b' + length c' + length d')


{-| Parsers -}

readNumber = read <$> (many $ oneOf "0123456789")

parseSRC :: Parsec String () String
parseSRC = manyTill anyChar (try $ string "SRC=")

parseIP :: Parsec String () IP
parseIP = do
  s1 <- readNumber <* char '.'
  s2 <- readNumber <* char '.'
  s3 <- readNumber <* char '.'
  s4 <- readNumber
  return $ IP s1 s2 s3 s4

parseTime :: Parsec String () Time
parseTime = do
  hour    <- readNumber <* char ':'
  minute  <- readNumber <* char ':'
  seconds <- readNumber
  return $ Time hour minute seconds

parseDate :: Parsec String () Date
parseDate = do
  month <- count 3 letter <* spaces
  day   <- readNumber
  return $ Date month day

parseLine :: Parsec String () Attempt
parseLine = do
  date <- parseDate <* spaces
  time <- parseTime <* parseSRC
  ip   <- parseIP
  return $ Attempt date time ip

parseLog :: [String] -> [Attempt]
parseLog log = do
  line <- log
  case parse parseLine "test" line of
    Right x -> [x]
    Left _  -> []


{-| Helper Functions -}

getTotalAttempts :: [Attempt] -> String
getTotalAttempts attempts = (show $ length attempts) ++ " access attempts."

currentAttempts :: [Attempt] -> CurrentLine -> [Attempt]
currentAttempts attempts line = (take 10 . drop line) attempts

printCurrentAttempts :: [Attempt] -> String
printCurrentAttempts = unlines . foldr printAttempt [] . zip [0..]

printAttempt :: (Int, Attempt) -> [String] -> [String]
printAttempt (x, y) ls = [show x ++ " - " ++ show y] ++ ls


{-| Selected IP Options -}

selectedIP :: [Attempt] -> CurrentLine -> Choice -> IO ()
selectedIP attempts currentLine choice = do 
    ipOptions
    userInput <- getChar
    case userInput of
        '1' -> do callCommand $ "whois " ++ 
                    (show $ currentIP) ++ " | less"
                  interactive attempts currentLine 
        '2' -> do callCommand $ "firefox " ++
                    "http://www.abuseat.org/lookup.cgi?ip=" ++
                    (show $ currentIP) ++ " &"
                  interactive attempts currentLine 
        'b' -> interactive attempts currentLine 
        _   -> (putStrLn $ "Invlaid Input") >>
               selectedIP attempts currentLine choice
  where currentIP = getIP $ attempts!!(currentLine + choice)
        ipOptions = putStr . unlines $
            concat $ ["Current IP: " ++ (show currentIP) ++ "\n"] : 
                     ["'1' Whois lookup"] :
                     ["'2' AbuseAt CBL Query (Using Firefox)"] :
                     ["\n"] :
                     ["'b' Back to previous page"] : []    


{-| Interactive Mode -}

interactive :: [Attempt] -> CurrentLine -> IO () 
interactive attempts currentLine = do
    putStrLn $ "\n"
    putStrLn $ printCurrentAttempts $ currentAttempts attempts currentLine
    determineOptions (length attempts) currentLine
    userInput <- getChar
    case userInput of
        'n' -> if currentLine < (length attempts - 10)
               then interactive attempts (currentLine + 10)
               else interactive attempts currentLine
        'p' -> if currentLine > 0
               then interactive attempts (currentLine - 10)
               else interactive attempts currentLine
        'q' -> exitSuccess
        _   -> do 
                 if userInput `elem` ['0'..'9']
                 then selectedIP attempts currentLine (digitToInt userInput)
                 else (putStrLn $ "\nInvalid Entry") >> 
                          interactive attempts currentLine
  where determineOptions total current = 
            putStr . unlines $
                concat $ ["\n"] :
                [if current < total then "'n' Next Page" else []] :
                [if current > 0 then "'p' Previous Page" else []] :
                ["'q' Quit"] : []

                
{-| Options Parser -}

options :: Parser Options
options = Options
    <$> switch ( long   "test"
               <> short 't'
               <> help  "Start in test mode" )
    <*> switch ( long   "interactive"
               <> short 'i'
               <> help  "Start in interactive mode" )
    <*> switch ( long   "verbose"
               <> short 'v'
               <> help  "Display in verbose mode" )

main :: IO ()
main = do
  userInput <- execParser opts

  let logFile = if (optTest userInput) 
                then "./data/testdata.log"
                else "/var/log/iptables.log"
  log <- lines <$> readFile logFile
  let parsedLog = parseLog log
  putStrLn $ getTotalAttempts parsedLog

  when (optInteractive userInput) $ do
    interactive parsedLog 0
    exitSuccess
  
  when (optVerbose userInput) $ do
    let allLogs = (unlines . foldr printAttempt [] . zip [0..]) parsedLog 
    putStrLn $ allLogs
    exitSuccess    

    where opts = info (options <**> helper)
            ( fullDesc
           <> progDesc "Manage and filter your IP tables"
           <> header   "IP FILTER MANAGER" )
