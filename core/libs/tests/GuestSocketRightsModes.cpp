#include "prx/libc/include/Api.hpp"
#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <fcntl.h>
#include <sys/socket.h>

static void Check(bool value, int line) {
    if (!value) {
        std::fprintf(stderr, "socket rights mode check failed at line %d, errno %d\n", line, *__error_nid_postfix());
        std::abort();
    }
}
#define Require(value) Check((value), __LINE__)

constexpr int Unix = 1;
constexpr int Stream = 1;
constexpr int Datagram = 2;
constexpr int SocketLevel = 0xffff;
constexpr int Rights = 1;
constexpr int GetFlags = 3;
constexpr int SetFlags = 4;
constexpr int ReadWrite = 2;
constexpr int NonBlocking = 4;
constexpr int DontWait = 0x80;
constexpr int ReceiveTimeout = 0x1006;
constexpr std::size_t Header = 16;
constexpr std::size_t ControlSpace = 24;
using Clock = std::chrono::steady_clock;

struct Descriptor {
    int value = -1;

    ~Descriptor() {
        if (value >= 0) close_nid_postfix(value);
    }

    void Close() {
        const int descriptor = value;
        value = -1;
        Require(descriptor >= 0 && close_nid_postfix(descriptor) == 0);
    }
};

struct Pair {
    std::array<int, 2> descriptors{-1, -1};

    explicit Pair(int type = Stream) {
        Require(socketpair_nid_postfix(Unix, type, 0, descriptors.data()) == 0);
    }

    ~Pair() {
        for (const int descriptor : descriptors) {
            if (descriptor >= 0) close_nid_postfix(descriptor);
        }
    }
};

struct Retained {
    std::shared_ptr<void> owner;
    std::uintptr_t native = 0;

    int Native() const {
        return static_cast<int>(native);
    }

    KernelSocketPoll::NativeOwner* Transport() const {
        auto* transport = static_cast<KernelSocketPoll::NativeOwner*>(owner.get());
        Require(transport != nullptr && transport->transfer != nullptr);
        return transport;
    }
};

static Retained Lookup(int descriptor) {
    Retained result;
    Require(KernelLookupSocketNative_nid_no_patch(descriptor, &result.owner, &result.native));
    Require(result.owner != nullptr);
    return result;
}

static int PassDescriptor(const Pair& carrier, int descriptor) {
    std::array<unsigned char, ControlSpace> control{};
    const std::uint32_t recordLength = Header + sizeof(int);
    std::memcpy(control.data(), &recordLength, sizeof(recordLength));
    std::memcpy(control.data() + 4, &SocketLevel, sizeof(SocketLevel));
    std::memcpy(control.data() + 8, &Rights, sizeof(Rights));
    std::memcpy(control.data() + Header, &descriptor, sizeof(descriptor));
    char payload = 'R';
    KernelIovec vector{&payload, 1};
    GuestMsghdr sending{};
    sending.iov = &vector;
    sending.iovLength = 1;
    sending.control = control.data();
    sending.controlLength = control.size();
    Require(sendmsg_nid_postfix(carrier.descriptors[0], &sending, 0) == 1);

    control.fill(0);
    payload = '?';
    GuestMsghdr receiving{};
    receiving.iov = &vector;
    receiving.iovLength = 1;
    receiving.control = control.data();
    receiving.controlLength = control.size();
    Require(recvmsg_nid_postfix(carrier.descriptors[1], &receiving, 0) == 1);
    Require(payload == 'R' && receiving.flags == 0 && receiving.controlLength == ControlSpace);
    std::uint32_t length = 0;
    int level = 0;
    int type = 0;
    int received = -1;
    std::memcpy(&length, control.data(), sizeof(length));
    std::memcpy(&level, control.data() + 4, sizeof(level));
    std::memcpy(&type, control.data() + 8, sizeof(type));
    std::memcpy(&received, control.data() + Header, sizeof(received));
    Require(length == recordLength && level == SocketLevel && type == Rights);
    Require(received >= 0 && received != descriptor);
    return received;
}

static KernelTimeval Timeout(int descriptor) {
    KernelTimeval value{-1, -1};
    std::uint32_t length = sizeof(value);
    Require(getsockopt_nid_postfix(descriptor, SocketLevel, ReceiveTimeout, &value, &length) == 0);
    Require(length == sizeof(value));
    return value;
}

struct PassedSocket {
    Pair source;
    Pair carrier{Datagram};
    Descriptor received;
    Retained original;
    Retained passed;
    Retained peer;

    explicit PassedSocket(bool nonblocking = false, bool timed = false) {
        if (nonblocking) Require(fcntl_nid_postfix(source.descriptors[0], SetFlags, ReadWrite | NonBlocking) == 0);
        if (timed) {
            const KernelTimeval timeout{0, 200000};
            Require(setsockopt_nid_postfix(source.descriptors[0], SocketLevel, ReceiveTimeout, &timeout, sizeof(timeout)) == 0);
        }
        received.value = PassDescriptor(carrier, source.descriptors[0]);
        original = Lookup(source.descriptors[0]);
        passed = Lookup(received.value);
        peer = Lookup(source.descriptors[1]);
        Require(original.Native() != passed.Native());
        const char sent = 'v';
        Require(::send(peer.Native(), &sent, 1, MSG_DONTWAIT | MSG_NOSIGNAL) == 1);
        char byte = '?';
        Require(recv_nid_postfix(received.value, &byte, 1, DontWait) == 1 && byte == sent);
    }
};

struct Flags {
    int originalGuest;
    int passedGuest;
    int originalNative;
    int passedNative;
};

static Flags ObserveFlags(const PassedSocket& socket, const char* mode) {
    const Flags flags{
        fcntl_nid_postfix(socket.source.descriptors[0], GetFlags),
        fcntl_nid_postfix(socket.received.value, GetFlags),
        ::fcntl(socket.original.Native(), F_GETFL),
        ::fcntl(socket.passed.Native(), F_GETFL)
    };
    Require(flags.originalGuest >= 0 && flags.passedGuest >= 0 && flags.originalNative >= 0 && flags.passedNative >= 0);
    std::fprintf(stderr, "%s: original guest=0x%x native=0x%x, received guest=0x%x native=0x%x\n",
        mode, flags.originalGuest, flags.originalNative, flags.passedGuest, flags.passedNative);
    return flags;
}

struct ReadResult {
    int value = -2;
    int error = 0;
    char byte = '?';
    std::int64_t milliseconds = 0;
    bool sent = false;
    int sentBytes = -2;
    int sendError = 0;
    bool released = false;
    int releaseResult = -2;
    int releaseError = 0;
};

static ReadResult ReadBounded(const Retained& socket, const Retained& peer, bool supplyData = false) {
    auto* transport = socket.Transport();
    std::mutex mutex;
    std::condition_variable changed;
    bool finished = false;
    ReadResult result;
    const auto started = Clock::now();
    std::jthread release([&] {
        std::unique_lock lock(mutex);
        if (supplyData) {
            if (changed.wait_for(lock, std::chrono::milliseconds(100), [&] { return finished; })) return;
            lock.unlock();
            const char byte = 'z';
            result.sent = true;
            result.sentBytes = static_cast<int>(::send(peer.Native(), &byte, 1, MSG_DONTWAIT | MSG_NOSIGNAL));
            result.sendError = errno;
            lock.lock();
        }
        if (changed.wait_for(lock, std::chrono::milliseconds(1500), [&] { return finished; })) return;
        lock.unlock();
        result.released = true;
        result.releaseResult = ::shutdown(peer.Native(), SHUT_WR);
        result.releaseError = errno;
    });
    errno = 0;
    result.value = transport->transfer(transport, false, &result.byte, 1);
    result.error = errno;
    result.milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
    {
        std::lock_guard lock(mutex);
        finished = true;
    }
    changed.notify_one();
    release.join();
    return result;
}

static void ReportRead(const char* mode, const ReadResult& result) {
    std::fprintf(stderr, "%s: retained read=%d errno=%d byte=%d elapsed=%lldms, sent=%d bytes=%d errno=%d, released=%d shutdown=%d errno=%d\n",
        mode, result.value, result.error, static_cast<unsigned char>(result.byte), static_cast<long long>(result.milliseconds),
        result.sent, result.sentBytes, result.sendError, result.released, result.releaseResult, result.releaseError);
}

static void RequireNativeNonblocking(const PassedSocket& socket, const Flags& flags) {
    Require((flags.originalNative & O_NONBLOCK) != 0 && (flags.passedNative & O_NONBLOCK) != 0);
    char byte = '?';
    errno = 0;
    const auto value = ::recv(socket.passed.Native(), &byte, 1, 0);
    const int error = errno;
    Require(value == -1 && error == EAGAIN && byte == '?');
}

static void CheckFlags() {
    PassedSocket socket{true};
    const auto flags = ObserveFlags(socket, "flags");
    RequireNativeNonblocking(socket, flags);
    Require(flags.originalGuest == (ReadWrite | NonBlocking));
    Require(flags.passedGuest == flags.originalGuest);
}

static void CheckOwner(bool alias) {
    PassedSocket socket{!alias};
    if (alias) {
        const auto before = ObserveFlags(socket, "alias before F_SETFL");
        Require(before.originalGuest == ReadWrite && before.passedGuest == ReadWrite);
        Require((before.originalNative & O_NONBLOCK) == 0 && (before.passedNative & O_NONBLOCK) == 0);
        Require(fcntl_nid_postfix(socket.source.descriptors[0], SetFlags, ReadWrite | NonBlocking) == 0);
    }
    const char* mode = alias ? "alias after F_SETFL" : "owner";
    const auto flags = ObserveFlags(socket, mode);
    RequireNativeNonblocking(socket, flags);
    socket.received.Close();
    const auto result = ReadBounded(socket.passed, socket.peer);
    ReportRead(mode, result);
    Require(!result.released && result.value == -1 && result.error == EAGAIN && result.byte == '?');
    Require(result.milliseconds < 1000);
    Require(flags.originalGuest == (ReadWrite | NonBlocking) && flags.passedGuest == flags.originalGuest);
}

static void CheckTimeout() {
    PassedSocket socket{false, true};
    const auto flags = ObserveFlags(socket, "timeout");
    Require((flags.originalNative & O_NONBLOCK) == 0 && (flags.passedNative & O_NONBLOCK) == 0);
    const auto original = Timeout(socket.source.descriptors[0]);
    const auto passed = Timeout(socket.received.value);
    std::fprintf(stderr, "timeout: original=%llds %lldus, received=%llds %lldus\n",
        static_cast<long long>(original.tv_sec), static_cast<long long>(original.tv_usec),
        static_cast<long long>(passed.tv_sec), static_cast<long long>(passed.tv_usec));
    Require(original.tv_sec == 0 && original.tv_usec >= 100000 && original.tv_usec <= 200000);
    socket.received.Close();
    const auto result = ReadBounded(socket.passed, socket.peer);
    ReportRead("timeout", result);
    Require(!result.released && result.value == -1 && result.error == EAGAIN && result.byte == '?');
    Require(result.milliseconds >= 100 && result.milliseconds < 1000);
    Require(passed.tv_sec == original.tv_sec && passed.tv_usec == original.tv_usec);
}

static void CheckBlocking() {
    PassedSocket socket;
    const auto flags = ObserveFlags(socket, "blocking");
    Require(flags.originalGuest == ReadWrite && flags.passedGuest == ReadWrite);
    Require((flags.originalNative & O_NONBLOCK) == 0 && (flags.passedNative & O_NONBLOCK) == 0);
    socket.received.Close();
    const auto result = ReadBounded(socket.passed, socket.peer, true);
    ReportRead("blocking", result);
    Require(result.sent && result.sentBytes == 1 && !result.released && result.value == 1 && result.byte == 'z');
    Require(result.milliseconds >= 50 && result.milliseconds < 1500);
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string_view mode = argv[1];
    if (mode == "flags") CheckFlags();
    else if (mode == "owner") CheckOwner(false);
    else if (mode == "alias") CheckOwner(true);
    else if (mode == "timeout") CheckTimeout();
    else if (mode == "blocking") CheckBlocking();
    else return 2;
    return 0;
}
