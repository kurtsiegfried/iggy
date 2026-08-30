// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Wait-strategy pacing for empty polls: spin first, then yield, then
//! park on the doorbell. Pure decision logic so the caller owns every
//! OS interaction and the crate stays free of runtime dependencies.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleStrategy {
    pub spin_limit: u32,
    pub yield_limit: u32,
}

impl Default for IdleStrategy {
    fn default() -> Self {
        Self {
            spin_limit: 1024,
            yield_limit: 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleAdvice {
    Spin,
    Yield,
    Park,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdleState {
    idle_rounds: u32,
}

impl IdleState {
    /// Called after an empty poll; returns what to do before the next
    /// one.
    pub const fn advise(&mut self, strategy: IdleStrategy) -> IdleAdvice {
        let round = self.idle_rounds;
        self.idle_rounds = self.idle_rounds.saturating_add(1);
        if round < strategy.spin_limit {
            IdleAdvice::Spin
        } else if round < strategy.spin_limit.saturating_add(strategy.yield_limit) {
            IdleAdvice::Yield
        } else {
            IdleAdvice::Park
        }
    }

    /// Called after a non-empty poll or a wake.
    pub const fn reset(&mut self) {
        self.idle_rounds = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_progresses_from_spin_to_yield_to_park() {
        let strategy = IdleStrategy {
            spin_limit: 2,
            yield_limit: 2,
        };
        let mut state = IdleState::default();
        assert_eq!(state.advise(strategy), IdleAdvice::Spin);
        assert_eq!(state.advise(strategy), IdleAdvice::Spin);
        assert_eq!(state.advise(strategy), IdleAdvice::Yield);
        assert_eq!(state.advise(strategy), IdleAdvice::Yield);
        assert_eq!(state.advise(strategy), IdleAdvice::Park);
        assert_eq!(state.advise(strategy), IdleAdvice::Park);
    }

    #[test]
    fn reset_returns_to_spinning() {
        let strategy = IdleStrategy {
            spin_limit: 1,
            yield_limit: 1,
        };
        let mut state = IdleState::default();
        state.advise(strategy);
        state.advise(strategy);
        assert_eq!(state.advise(strategy), IdleAdvice::Park);
        state.reset();
        assert_eq!(state.advise(strategy), IdleAdvice::Spin);
    }
}
