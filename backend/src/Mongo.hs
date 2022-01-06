module Mongo (
  Execution,
  execution
) where

import Database.MongoDB

type Execution = (forall a. Action IO a -> IO a)

execution :: Pipe -> Execution
execution pipe = access pipe master "em"