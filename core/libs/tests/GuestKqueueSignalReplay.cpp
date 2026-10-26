#include "prx/libc/include/Api.hpp"
#include "prx/libkernel/include/Api.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <string_view>

using Handler = void (APS5_VABI *)(int);

constexpr int LowSignal = 30;
constexpr int HighSignal = 31;
constexpr int NativeSignal = 15;
constexpr int SetMask = 3;
constexpr int Unblock = 2;
constexpr std::int16_t SignalFilter = -6;
constexpr std::uint16_t AddEvent = 1;

static void Check(bool value, int line) {
    if (value) return;
    std::fprintf(stderr, "signal replay check failed at line %d, errno %d\n", line, *__error_nid_postfix());
    std::abort();
}
#define Require(value) Check((value), __LINE__)

static GuestSignalSet Signals(std::initializer_list<int> values) {
    GuestSignalSet set{};
    Require(sigemptyset_nid_postfix(&set) == 0);
    for (const int signal : values) Require(sigaddset_nid_postfix(&set, signal) == 0);
    return set;
}

static bool Contains(const GuestSignalSet& set, int signal) {
    const unsigned bit = static_cast<unsigned>(signal - 1);
    return (set.bits[bit / 32] & (1u << (bit % 32))) != 0;
}

static bool Pending(int signal) {
    GuestSignalSet set{};
    Require(sigpending_nid_postfix(&set) == 0);
    return Contains(set, signal);
}

class Mask {
public:
    explicit Mask(const GuestSignalSet& set) {
        Require(pthread_sigmask_nid_postfix(SetMask, &set, &previous) == 0);
    }
    ~Mask() {
        Require(pthread_sigmask_nid_postfix(SetMask, &previous, nullptr) == 0);
    }
    void Release(int signal) {
        const auto set = Signals({signal});
        Require(pthread_sigmask_nid_postfix(Unblock, &set, nullptr) == 0);
    }
private:
    GuestSignalSet previous{};
};

class Disposition {
public:
    Disposition(int signal, Handler handler, const GuestSignalSet& mask = {}) : signal(signal) {
        const GuestSigaction action{reinterpret_cast<std::uintptr_t>(handler), 0, mask};
        Require(sigaction_nid_postfix(signal, &action, &previous) == 0);
    }
    ~Disposition() {
        Require(sigaction_nid_postfix(signal, &previous, nullptr) == 0);
    }
private:
    int signal;
    GuestSigaction previous{};
};

class Queue {
public:
    Queue(std::initializer_list<int> signals) : descriptor(kqueue_nid_postfix()) {
        Require(descriptor >= 0);
        for (const int signal : signals) {
            KernelEvent event{};
            event.ident = signal;
            event.filter = SignalFilter;
            event.flags = AddEvent;
            Require(kevent_nid_postfix(descriptor, &event, 1, nullptr, 0, nullptr) == 0);
        }
    }
    ~Queue() {
        Require(close_nid_postfix(descriptor) == 0);
    }
    int Poll(KernelEvent& event) const {
        const KernelTimespec zero{};
        return kevent_nid_postfix(descriptor, nullptr, 0, &event, 1, &zero);
    }
    void Take(int signal, std::intptr_t count) const {
        KernelEvent event{};
        Require(Poll(event) == 1);
        Require(event.ident == static_cast<std::uintptr_t>(signal) && event.filter == SignalFilter && event.data == count);
    }
    void Empty() const {
        KernelEvent event{};
        Require(Poll(event) == 0);
    }
private:
    int descriptor;
};

static std::atomic<int> lowCalls{0};
static std::atomic<int> highCalls{0};
static std::atomic<int> nativeCalls{0};
static std::atomic<int> nestedResult{0};
static std::atomic<int> observedInsideHandler{0};
static_assert(std::atomic<int>::is_always_lock_free);

static void APS5_VABI LowHandler(int) {
    lowCalls.fetch_add(1);
}

static void APS5_VABI HighHandler(int) {
    highCalls.fetch_add(1);
}

static void GenerateLow() {
    if (raise_nid_postfix(LowSignal) != 0 || raise_nid_postfix(LowSignal) != 0) nestedResult.store(-1);
    observedInsideHandler.store(lowCalls.load());
}

static void APS5_VABI NativeHandler(int) {
    nativeCalls.fetch_add(1);
    GenerateLow();
}

static void APS5_VABI OrderedHandler(int) {
    highCalls.fetch_add(1);
    GenerateLow();
}

static void SelfReplay() {
    Disposition low(LowSignal, LowHandler);
    Disposition high(HighSignal, HighHandler);
    Mask blocked(Signals({LowSignal, HighSignal}));
    Queue lowQueue{LowSignal};
    Queue highQueue{HighSignal};
    for (int index = 0; index < 3; ++index) Require(raise_nid_postfix(LowSignal) == 0);
    for (int index = 0; index < 2; ++index) Require(raise_nid_postfix(HighSignal) == 0);
    Require(lowCalls.load() == 0 && highCalls.load() == 0 && Pending(LowSignal) && Pending(HighSignal));
    lowQueue.Take(LowSignal, 3);
    highQueue.Take(HighSignal, 2);
    blocked.Release(LowSignal);
    Require(lowCalls.load() == 1 && highCalls.load() == 0 && !Pending(LowSignal) && Pending(HighSignal));
    lowQueue.Empty();
    highQueue.Empty();
    blocked.Release(HighSignal);
    Require(lowCalls.load() == 1 && highCalls.load() == 1 && !Pending(HighSignal));
    lowQueue.Empty();
    highQueue.Empty();
    std::puts("signal replay self: five generations, two coalesced deliveries, no replay counts");
}

static void HandlerReplay() {
    Disposition low(LowSignal, LowHandler);
    Disposition native(NativeSignal, NativeHandler, Signals({LowSignal}));
    Mask unblocked(Signals({}));
    Queue lowQueue{LowSignal};
    Queue nativeQueue{NativeSignal};
    Require(raise_nid_postfix(NativeSignal) == 0);
    const int delivered = lowCalls.load();
    const int inside = observedInsideHandler.load();
    std::fprintf(stderr, "signal replay handler: outer=%d nested=%d inside=%d error=%d\n",
        nativeCalls.load(), delivered, inside, nestedResult.load());
    Require(nativeCalls.load() == 1 && delivered == 1 && inside == 0 && nestedResult.load() == 0);
    nativeQueue.Take(NativeSignal, 1);
    lowQueue.Take(LowSignal, 2);
    nativeQueue.Empty();
    lowQueue.Empty();
}

static void OrderedReplay() {
    Disposition low(LowSignal, LowHandler);
    Disposition high(HighSignal, OrderedHandler, Signals({LowSignal}));
    Mask blocked(Signals({HighSignal}));
    Queue lowQueue{LowSignal};
    Queue highQueue{HighSignal};
    Require(raise_nid_postfix(HighSignal) == 0 && raise_nid_postfix(HighSignal) == 0);
    Require(Pending(HighSignal) && highCalls.load() == 0 && lowCalls.load() == 0);
    highQueue.Take(HighSignal, 2);
    blocked.Release(HighSignal);
    const int delivered = lowCalls.load();
    std::fprintf(stderr, "signal replay handler-order: outer=%d nested=%d inside=%d error=%d\n",
        highCalls.load(), delivered, observedInsideHandler.load(), nestedResult.load());
    Require(highCalls.load() == 1 && delivered == 1 && observedInsideHandler.load() == 0 && nestedResult.load() == 0);
    highQueue.Empty();
    lowQueue.Take(LowSignal, 2);
    lowQueue.Empty();
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string_view mode = argv[1];
    if (mode == "self") SelfReplay();
    else if (mode == "handler") HandlerReplay();
    else if (mode == "handler-order") OrderedReplay();
    else return 2;
    return 0;
}
