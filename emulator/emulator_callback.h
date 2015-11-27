#ifndef DIVERT_EMULATOR_CALLBACK_H
#define DIVERT_EMULATOR_CALLBACK_H

void emulator_callback(void *, void *, struct ip *, struct sockaddr *);

void *emulator_thread_func(void *args);

enum {
    QUIT_THREAD = -1,
    NEW_PACKET = 0,
    STAGE_CHECK_SIZE,
    STAGE_DROP,
    STAGE_DELAY,
    STAGE_THROTTLE,
    STAGE_DISORDER,
    STAGE_TAMPER,
    STAGE_DUPLICATE,
};

#endif //DIVERT_EMULATOR_CALLBACK_H
