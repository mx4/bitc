#pragma once

struct poolworker_state;

typedef void (poolworker_func)(void *clientData);

struct poolworker_state * poolworker_create(int numThreads);
void poolworker_destroy(struct poolworker_state *pw);
void poolworker_wait(struct poolworker_state *pw);
void poolworker_wait_for_one_cmp(struct poolworker_state *pw);

void poolworker_queue_work(struct poolworker_state *pw,
                           poolworker_func *func, void *clientData);

