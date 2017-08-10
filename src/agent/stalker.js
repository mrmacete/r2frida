/* eslint-disable comma-dangle */
'use strict';

const eventsByThread = {};

module.exports = {
  stalkFunction: stalkFunction,
  unfollowAll: unfollowAll
};

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
          hook.detach();
          setTimeout(() => {
            resolve(eventsByThread[this.hreadId]);
            delete eventsByThread[this.hreadId];
          }, 1000);
        }
      }
    });
  });
}

function _followHere (config) {
  const threadId = Process.getCurrentThreadId();

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
    compile: false
  };

  events[config.event] = true;

  return events;
}

function logWarning (message) {
  console.log(message);
}

/* globals Interceptor, Stalker */
