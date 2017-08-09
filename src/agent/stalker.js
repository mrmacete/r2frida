/* eslint-disable comma-dangle */
'use strict';

const eventsByThread = {};
const threadIds = new Set();

module.exports = {
  stalkFromTo: stalkFromTo,
  stalkFunction: stalkFunction,
  unfollowAll: unfollowAll
};

function stalkFromTo (config, from, to) {
  return new Promise((resolve, reject) => {
    let threadId = null;

    Interceptor.attach(from, function () {
      threadId = _followHere(config);
    });

    Interceptor.attach(to, function () {
      if (threadId === null) {
        logWarning('ignoring unfollow happening before follow');
        return;
      }

      const thisThreadId = Process.getCurrentThreadId();

      if (thisThreadId === threadId) {
        _unfollowHere();
        threadIds.delete(Process.getCurrentThreadId());
        setTimeout(() => {
          resolve(eventsByThread[threadId]);
          delete eventsByThread[threadId];
        }, 1000);
      }
    });
  });
}

function stalkFunction (config, address) {
  return new Promise((resolve, reject) => {
    let recursiveCountByThread = {};
    const hook = Interceptor.attach(address, {
      onEnter () {
        this.hreadId = Process.getCurrentThreadId();
        let recursiveCount = recursiveCountByThread[this.hreadId] || 0;
        recursiveCount++;
        recursiveCountByThread[this.hreadId] = recursiveCount;

        if (recursiveCount === 1) {
          _followHere(config);
        }
      },

      onLeave () {
        let recursiveCount = recursiveCountByThread[this.hreadId];
        recursiveCount--;
        recursiveCountByThread[this.hreadId] = recursiveCount;

        if (recursiveCount === 0) {
          _unfollowHere();
          threadIds.delete(Process.getCurrentThreadId());
          hook.detach();
          setTimeout(() => {
            resolve(eventsByThread[this.hreadId]);
            delete eventsByThread[this.hreadId];
          }, 1000);
        }
      }
    });
    console.log('HOOK DONE GO GO GO');
  });
}

function _followHere (config) {
  const threadId = Process.getCurrentThreadId();
  if (threadIds.has(threadId)) {
    _unfollowHere();
    eventsByThread[threadId] = [];
  }

  threadIds.add(threadId);

  Stalker.follow(threadId, {
    events: _eventsFromConfig(config),
    onReceive: function (events) {
      const parsed = Stalker.parse(events, {annotate: false});

      if (threadId in eventsByThread) {
        eventsByThread[threadId].push(...parsed);
      } else {
        eventsByThread[threadId] = parsed;
      }
    }
  });

  return threadId;
}

function _unfollowHere () {
  Stalker.unfollow();
}

function unfollowAll () {
  const threads = Process.enumerateThreadsSync();
  for (const thread of threads) {
    Stalker.unfollow(thread.id);
  }
}

function _eventsFromConfig (config) {
  const events = {
    call: false,
    ret: false,
    exec: false,
    block: false,
    compile: true
  };

  return events;
}

function logWarning (message) {
  console.log(message);
}

/* globals Interceptor, Stalker */
