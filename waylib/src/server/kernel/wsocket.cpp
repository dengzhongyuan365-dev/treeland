// Copyright (C) 2023 JiDe Zhang <zhangjide@deepin.org>.
// SPDX-License-Identifier: Apache-2.0 OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#include "wsocket.h"
#include "private/wglobal_p.h"

#include <QDir>
#include <QStandardPaths>
#include <QStringDecoder>
#include <QPointer>

#include <wayland-server-core.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <signal.h>

#include <memory>
#include <utility>

struct wl_event_source;

WAYLIB_SERVER_BEGIN_NAMESPACE

// Socket management and client connections
Q_LOGGING_CATEGORY(waylibSocket, "waylib.server.socket", QtInfoMsg)

#define LOCK_SUFFIX ".lock"

/**
 * @brief RAII wrapper for file descriptors with automatic cleanup
 * 
 * This class provides automatic management of file descriptors, ensuring
 * they are properly closed when the object goes out of scope. It follows
 * RAII principles and supports move semantics for efficient resource transfer.
 */
class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) noexcept : m_fd(fd) {}
    ~FileDescriptor() { reset(); }

    // Non-copyable but movable
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    FileDescriptor(FileDescriptor&& other) noexcept : m_fd(other.release()) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        reset(other.release());
        return *this;
    }

    int get() const noexcept { return m_fd; }
    
    int release() noexcept {
        int fd = m_fd;
        m_fd = -1;
        return fd;
    }

    void reset(int fd = -1) noexcept {
        if (m_fd >= 0 && m_fd != fd) {
            ::close(m_fd);
        }
        m_fd = fd;
    }

    bool isValid() const noexcept { return m_fd >= 0; }
    operator bool() const noexcept { return isValid(); }

private:
    int m_fd;
};

/**
 * @brief Utility functions for consistent error handling and logging
 * 
 * These functions provide standardized logging patterns throughout the socket
 * implementation, improving consistency and maintainability.
 */
namespace SocketUtils {
    /// Log system errors with errno information
    inline void logSystemError(const QString& operation, const QString& context) {
        qCWarning(waylibSocket) << operation << "failed for" << context 
                               << ":" << QString::fromLocal8Bit(strerror(errno));
    }

    /// Log warning messages with optional context
    inline void logWarning(const QString& message, const QString& context = QString()) {
        if (context.isEmpty()) {
            qCWarning(waylibSocket) << message;
        } else {
            qCWarning(waylibSocket) << message << context;
        }
    }

    /// Log debug messages with optional context
    inline void logDebug(const QString& message, const QString& context = QString()) {
        if (context.isEmpty()) {
            qCDebug(waylibSocket) << message;
        } else {
            qCDebug(waylibSocket) << message << context;
        }
    }
}

/**
 * @brief Socket locking utilities for Wayland socket management
 * 
 * These functions handle the creation and management of socket lock files
 * to prevent multiple compositor instances from binding to the same socket.
 */
namespace SocketLocking {
    
    /// Create and open a lock file for the given socket path
    FileDescriptor createLockFile(const QString& socketPath) {
        const QString lockFile = socketPath + LOCK_SUFFIX;
        const auto lockFilePath = lockFile.toUtf8();

        int fd = open(lockFilePath.constData(), O_CREAT | O_CLOEXEC | O_RDWR,
                     (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP));

        if (fd < 0) {
            SocketUtils::logWarning("Failed to open lockfile - please check file permissions", lockFile);
            return FileDescriptor(-1);
        }

        return FileDescriptor(fd);
    }

    /// Acquire an exclusive lock on the file descriptor
    bool acquireFileLock(int fd, const QString& lockFile) {
        if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
            SocketUtils::logWarning("Failed to lock - another compositor may be running", lockFile);
            return false;
        }
        return true;
    }

    /// Check if socket file exists and clean it up if needed
    bool validateAndCleanupSocket(const QString& socketPath) {
        struct stat socket_stat;
        const QByteArray socketPathBytes = socketPath.toUtf8();

        if (lstat(socketPathBytes.constData(), &socket_stat) < 0) {
            if (errno != ENOENT) {
                SocketUtils::logSystemError("Failed to stat file", socketPath);
                return false;
            }
            // File doesn't exist, which is fine
            return true;
        } 

        // Check if socket file has write permissions that might indicate stale socket
        if (socket_stat.st_mode & S_IWUSR || socket_stat.st_mode & S_IWGRP) {
            SocketUtils::logDebug("Removing existing socket file", socketPath);
            unlink(socketPathBytes.constData());
        }

        return true;
    }
}

/**
 * @brief Wayland socket locking implementation (adapted from libwayland)
 * 
 * This function creates a lock file for the given socket path to prevent
 * multiple compositor instances from binding to the same socket. The lock
 * is acquired exclusively and the existing socket file is cleaned up if
 * it appears to be stale.
 * 
 * @param socketFile Path to the socket file to lock
 * @return File descriptor for the lock file, or -1 on failure
 */
static int wl_socket_lock(const QString &socketFile)
{
    // Create and open lock file
    FileDescriptor lockFd = SocketLocking::createLockFile(socketFile);
    if (!lockFd.isValid()) {
        return -1;
    }

    // Acquire exclusive lock
    const QString lockFile = socketFile + LOCK_SUFFIX;
    if (!SocketLocking::acquireFileLock(lockFd.get(), lockFile)) {
        return -1;
    }

    // Validate and cleanup existing socket if needed
    if (!SocketLocking::validateAndCleanupSocket(socketFile)) {
        return -1;
    }

    // Success - release ownership of file descriptor
    return lockFd.release();
}

// File descriptor utilities
namespace FileDescriptorUtils {
    
    // Set CLOEXEC flag on file descriptor or close it on failure
    int setCloexecOrClose(int fd) {
        if (fd == -1) {
            return -1;
        }

        const long flags = fcntl(fd, F_GETFD);
        if (flags == -1) {
            ::close(fd);
            return -1;
        }

        if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            ::close(fd);
            return -1;
        }

        return fd;
    }

    // Create socket with CLOEXEC flag
    int createCloexecSocket(int domain, int type, int protocol) {
        // Try with SOCK_CLOEXEC first (modern systems)
        int fd = socket(domain, type | SOCK_CLOEXEC, protocol);
        if (fd >= 0) {
            return fd;
        }

        // Fall back to manual CLOEXEC setting if SOCK_CLOEXEC not supported
        if (errno != EINVAL) {
            return -1;
        }

        fd = socket(domain, type, protocol);
        return setCloexecOrClose(fd);
    }

    // Accept connection with CLOEXEC flag  
    int acceptCloexecConnection(int sockfd, sockaddr *addr, socklen_t *addrlen) {
        const int fd = accept(sockfd, addr, addrlen);
        return setCloexecOrClose(fd);
    }
}

static int set_cloexec_or_close(int fd)
{
    return FileDescriptorUtils::setCloexecOrClose(fd);
}

static int wl_os_socket_cloexec(int domain, int type, int protocol)
{
    return FileDescriptorUtils::createCloexecSocket(domain, type, protocol);
}

static int wl_os_accept_cloexec(int sockfd, sockaddr *addr, socklen_t *addrlen)
{
    return FileDescriptorUtils::acceptCloexecConnection(sockfd, addr, addrlen);
}
// Copy end

class Q_DECL_HIDDEN WSocketPrivate : public WObjectPrivate
{
public:
    WSocketPrivate(WSocket *qq, bool freeze, WSocket *parent)
        : WObjectPrivate(qq)
        , freezeClientWhenDisable(freeze)
        , parentSocket(parent)
    {}

    static WSocketPrivate *get(WSocket *qq) {
        return qq->d_func();
    }

    void shutdown();
    void restore();

    void addClient(WClient *client);

    W_DECLARE_PUBLIC(WSocket)

    bool enabled = true;
    const bool freezeClientWhenDisable;
    int fd = -1;
    int fd_lock = -1;
    bool ownsFd = true;
    QString socket_file;
    QPointer<WSocket> parentSocket;

    wl_display *display = nullptr;
    wl_event_source *eventSource = nullptr;
    QList<WClient*> clients;
};

struct Q_DECL_HIDDEN WlClientDestroyListener {
    WlClientDestroyListener(WClient *client)
        : client(client)
    {
        destroy.notify = handle_destroy;
    }

    ~WlClientDestroyListener();

    static WlClientDestroyListener *get(const wl_client *client);
    static void handle_destroy(struct wl_listener *listener, void *);

    wl_listener destroy;
    QPointer<WClient> client;
};

WlClientDestroyListener::~WlClientDestroyListener()
{
    wl_list_remove(&destroy.link);
}

WlClientDestroyListener *WlClientDestroyListener::get(const wl_client *client)
{
    wl_listener *listener = wl_client_get_destroy_listener(const_cast<wl_client*>(client),
                                                           WlClientDestroyListener::handle_destroy);
    if (!listener) {
        return nullptr;
    }

    WlClientDestroyListener *tmp = wl_container_of(listener, tmp, destroy);
    return tmp;
}

// Client management utilities
namespace ClientManagement {
    
    // Pause or resume a client process using signals
    bool pauseClient(wl_client *client, bool pause) {
        if (!client) {
            return false;
        }

        pid_t pid = 0;
        wl_client_get_credentials(client, &pid, nullptr, nullptr);

        if (pid == 0) {
            SocketUtils::logWarning("Cannot get valid PID for client");
            return false;
        }

        const int signal = pause ? SIGSTOP : SIGCONT;
        const bool success = (kill(pid, signal) == 0);
        
        if (!success) {
            SocketUtils::logSystemError(pause ? "Failed to pause client" : "Failed to resume client", 
                                       QString("PID: %1").arg(pid));
        } else {
            SocketUtils::logDebug(pause ? "Client paused successfully" : "Client resumed successfully",
                                 QString("PID: %1").arg(pid));
        }

        return success;
    }
}

static bool pauseClient(wl_client *client, bool pause)
{
    return ClientManagement::pauseClient(client, pause);
}

void WSocketPrivate::shutdown()
{
    if (!freezeClientWhenDisable)
        return;

    for (auto client : std::as_const(clients)) {
        client->freeze();
    }
}

void WSocketPrivate::restore()
{
    if (!freezeClientWhenDisable)
        return;

    for (auto client : std::as_const(clients)) {
        client->activate();
    }
}

void WSocketPrivate::addClient(WClient *client)
{
    Q_ASSERT(!clients.contains(client));
    clients.append(client);

    if (!enabled && freezeClientWhenDisable) {
        client->freeze();
    }

    W_Q(WSocket);

    Q_EMIT q->clientAdded(client);
    Q_EMIT q->clientsChanged();
}

class Q_DECL_HIDDEN WClientPrivate : public WObjectPrivate
{
public:
    WClientPrivate(wl_client *handle, WSocket *socket, WClient *qq)
        : WObjectPrivate(qq)
        , handle(handle)
        , socket(socket)
    {
        auto listener = new WlClientDestroyListener(qq);
        wl_client_add_destroy_listener(handle, &listener->destroy);
    }

    ~WClientPrivate() {
        if (pidFD >= 0)
            close(pidFD);

        if (handle) {
            auto listener = WlClientDestroyListener::get(handle);
            Q_ASSERT(listener);
            delete listener;
        }
    }

    W_DECLARE_PUBLIC(WClient)

    wl_client *handle = nullptr;
    WSocket *socket = nullptr;
    mutable QSharedPointer<WClient::Credentials> credentials;
    mutable int pidFD = -1;
};

void WlClientDestroyListener::handle_destroy(wl_listener *listener, void *data)
{
    WlClientDestroyListener *self = wl_container_of(listener, self, destroy);
    if (self->client) {
        Q_ASSERT(reinterpret_cast<wl_client*>(data) == self->client->handle());
        self->client->d_func()->handle = nullptr;
        auto socket = self->client->socket();
        Q_ASSERT(socket);
        bool ok = socket->removeClient(self->client);
        Q_ASSERT(ok);
    }

    delete self;
}

WClient::WClient(wl_client *client, WSocket *socket)
    : QObject(nullptr)
    , WObject(*new WClientPrivate(client, socket, this))
{

}

WSocket *WClient::socket() const
{
    W_DC(WClient);
    return d->socket;
}

wl_client *WClient::handle() const
{
    W_DC(WClient);
    return d->handle;
}

QSharedPointer<WClient::Credentials> WClient::credentials() const
{
    W_D(const WClient);

    if (!d->credentials) {
        d->credentials = getCredentials(handle());
    }

    return d->credentials;
}

int WClient::pidFD() const
{
    W_D(const WClient);

    if (d->pidFD == -1) {
        d->pidFD = syscall(SYS_pidfd_open, credentials()->pid, 0);
    }

    return d->pidFD;
}

QSharedPointer<WClient::Credentials> WClient::getCredentials(const wl_client *client)
{
    QSharedPointer<Credentials> credentials(new Credentials);
    wl_client_get_credentials(const_cast<wl_client*>(client),
                              &credentials->pid,
                              &credentials->uid,
                              &credentials->gid);

    return credentials;
}

WClient *WClient::get(const wl_client *client)
{
    if (auto tmp = WlClientDestroyListener::get(client))
        return tmp->client;
    return nullptr;
}

void WClient::freeze()
{
    W_D(WClient);
    pauseClient(d->handle, true);
}

void WClient::activate()
{
    W_D(WClient);
    pauseClient(d->handle, false);
}

WSocket::WSocket(bool freezeClientWhenDisable, WSocket *parentSocket, QObject *parent)
    : QObject(parent)
    , WObject(*new WSocketPrivate(this, freezeClientWhenDisable, parentSocket))
{

}

WSocket::~WSocket()
{
    close();
}

WSocket *WSocket::get(const wl_client *client)
{
    if (auto c = WClient::get(client))
        return c->socket();
    return nullptr;
}

WSocket *WSocket::parentSocket() const
{
    W_DC(WSocket);
    return d->parentSocket.get();
}

WSocket *WSocket::rootSocket() const
{
    W_DC(WSocket);
    return d->parentSocket ? d->parentSocket->rootSocket() : const_cast<WSocket*>(this);
}

bool WSocket::isValid() const
{
    W_DC(WSocket);
    return d->fd >= 0;
}

void WSocket::close()
{
    W_D(WSocket);

    if (d->eventSource) {
        wl_event_source_remove(d->eventSource);
        d->eventSource = nullptr;
        d->display = nullptr;
        Q_EMIT listeningChanged();
    }
    Q_ASSERT(!d->display);

    if (d->ownsFd) {
        if (d->fd >= 0) {
            ::close(d->fd);
            d->fd = -1;
            Q_EMIT validChanged();
        }
        if (d->fd_lock >= 0) {
            ::close(d->fd_lock);
            d->fd_lock = -1;
        }
    } else {
        Q_ASSERT(d->fd_lock < 0);
    }

    if (!d->clients.isEmpty()) {
        for (auto client : std::as_const(d->clients))
            delete client;

        d->clients.clear();
        Q_EMIT clientsChanged();
    }
}

SOCKET WSocket::socketFd() const
{
    W_DC(WSocket);
    return d->fd;
}

QString WSocket::fullServerName() const
{
    W_DC(WSocket);
    return d->socket_file;
}

bool WSocket::autoCreate(const QString &directory)
{
    // A reasonable number of maximum default sockets. If
    // you need more than this, use other API.
    constexpr int MAX_DISPLAYNO = 32;

    QString dir;

    if (directory.isEmpty()) {
        dir = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        if (dir.isEmpty() || dir == QDir::rootPath())
            return false;
    } else {
        dir = directory;
    }

    for (int i = 0; i < MAX_DISPLAYNO; ++i) {
        if (create(QString("%1/wayland-%2").arg(dir).arg(i)))
            return true;
    }

    return false;
}

/**
 * @brief Socket creation and configuration utilities
 * 
 * These functions handle the creation, binding, and configuration of Unix
 * domain sockets used for Wayland communication.
 */
namespace SocketCreation {
    
    /// Create and bind a Unix domain socket to the specified path
    bool createAndBindSocket(int socketFd, const QString& filePath) {
        const QByteArray pathBytes = filePath.toUtf8();
        sockaddr_un addr{};
        addr.sun_family = AF_LOCAL;
        
        const size_t pathLength = qMin(size_t(sizeof(addr.sun_path)), 
                                      size_t(pathBytes.size()) + 1);
        qstrncpy(addr.sun_path, pathBytes.constData(), pathLength);
        
        const socklen_t addrSize = offsetof(sockaddr_un, sun_path) + pathLength;
        
        if (::bind(socketFd, reinterpret_cast<const sockaddr*>(&addr), addrSize) < 0) {
            SocketUtils::logSystemError("Socket bind failed", filePath);
            return false;
        }
        
        return true;
    }

    /// Set socket to listening mode with standard Wayland backlog size
    bool enableSocketListening(int socketFd, const QString& context) {
        constexpr int BACKLOG_SIZE = 128; // Standard backlog size for Wayland sockets
        
        if (::listen(socketFd, BACKLOG_SIZE) < 0) {
            SocketUtils::logSystemError("Socket listen failed", context);
            return false;
        }
        
        SocketUtils::logDebug("Socket listening enabled", context);
        return true;
    }
}

bool WSocket::create(const QString &filePath)
{
    W_D(WSocket);

    if (isValid()) {
        SocketUtils::logWarning("Socket already valid, cannot create");
        return false;
    }

    // Create socket with CLOEXEC flag
    d->fd = wl_os_socket_cloexec(PF_LOCAL, SOCK_STREAM, 0);
    if (d->fd < 0) {
        SocketUtils::logSystemError("Failed to create socket", filePath);
        return false;
    }

    d->ownsFd = true;
    
    // Acquire socket lock
    d->fd_lock = wl_socket_lock(filePath);
    if (d->fd_lock < 0) {
        SocketUtils::logWarning("Failed to acquire socket lock", filePath);
        close();
        return false;
    }

    // Bind socket to path
    if (!SocketCreation::createAndBindSocket(d->fd, filePath)) {
        close();
        return false;
    }

    // Enable listening
    if (!SocketCreation::enableSocketListening(d->fd, filePath)) {
        close();
        return false;
    }

    // Update socket file path if changed
    if (d->socket_file != filePath) {
        d->socket_file = filePath;
        Q_EMIT fullServerNameChanged();
    }

    SocketUtils::logDebug("Socket created successfully", filePath);
    Q_EMIT validChanged();

    return true;
}

// Socket validation utilities
namespace SocketValidation {
    
    // Validate that file descriptor is a socket
    bool validateSocketDescriptor(int fd) {
        struct ::stat stat_buf{};
        if (fstat(fd, &stat_buf) != 0) {
            SocketUtils::logWarning("Failed to fstat file descriptor");
            return false;
        }
        
        if (!S_ISSOCK(stat_buf.st_mode)) {
            SocketUtils::logWarning("File descriptor is not a socket");
            return false;
        }
        
        return true;
    }

    // Check if socket is in listening mode
    bool validateListeningSocket(int fd) {
        int accept_conn = 0;
        socklen_t accept_conn_size = sizeof(accept_conn);
        
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accept_conn, &accept_conn_size) != 0) {
            SocketUtils::logSystemError("Failed to get socket options", QString::number(fd));
            return false;
        }
        
        if (accept_conn == 0) {
            SocketUtils::logWarning("File descriptor is not in listening mode");
            return false;
        }
        
        return true;
    }

    // Extract socket path from file descriptor
    QString extractSocketPath(int fd) {
        struct ::sockaddr_un addr;
        socklen_t len = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        
        // Try getpeername first, fallback to getsockname
        const int getpeernameStatus = ::getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len);
        if (getpeernameStatus != 0 || len == offsetof(sockaddr_un, sun_path)) {
            len = sizeof(addr);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
                return {};
            }
        }

        if (len <= offsetof(::sockaddr_un, sun_path)) {
            return {};
        }
        
        len -= offsetof(::sockaddr_un, sun_path);
        return decodeSocketPath(addr.sun_path, len);
    }

    // Decode socket path from raw data, handling null termination properly
    QString decodeSocketPath(const char* pathData, socklen_t pathLength) {
        QStringDecoder toUtf16(QStringDecoder::System, QStringDecoder::Flag::Stateless);
        QByteArrayView textData(pathData, pathLength);
        QString name = toUtf16(textData);
        
        if (name.isEmpty() || toUtf16.hasError()) {
            return {};
        }

        // Remove trailing null characters (not allowed in filenames for non-abstract namespace)
        if (!name.isEmpty() && name.at(name.size() - 1) == QChar::fromLatin1('\0')) {
            int truncPos = name.size() - 1;
            while (truncPos > 0 && name.at(truncPos - 1) == QChar::fromLatin1('\0')) {
                --truncPos;
            }
            name.truncate(truncPos);
        }

        return name;
    }
}

static QString getSocketFile(int fd, bool doCheck) {
    // Validate socket if requested
    if (doCheck) {
        if (!SocketValidation::validateSocketDescriptor(fd) || 
            !SocketValidation::validateListeningSocket(fd)) {
            return {};
        }
    }

    // Extract and return socket path
    return SocketValidation::extractSocketPath(fd);
}

bool WSocket::create(int fd, bool doListen)
{
    W_D(WSocket);

    if (isValid()) {
        SocketUtils::logWarning("Socket already valid, cannot create from file descriptor");
        return false;
    }

    const QString socketFile = getSocketFile(fd, true);
    if (socketFile.isEmpty()) {
        SocketUtils::logWarning("Failed to extract socket path from file descriptor");
        return false;
    }

    if (doListen && !SocketCreation::enableSocketListening(fd, socketFile)) {
        return false;
    }

    d->fd = fd;
    d->ownsFd = true;

    if (d->socket_file != socketFile) {
        d->socket_file = socketFile;
        Q_EMIT fullServerNameChanged();
    }

    SocketUtils::logDebug("Socket created from file descriptor", socketFile);
    Q_EMIT validChanged();

    return true;
}

bool WSocket::bind(int fd)
{
    W_D(WSocket);

    if (isValid()) {
        SocketUtils::logWarning("Socket already valid, cannot bind to new file descriptor");
        return false;
    }

    d->fd = fd;
    d->ownsFd = false;
    d->socket_file = getSocketFile(fd, false);

    if (d->socket_file.isEmpty()) {
        SocketUtils::logWarning("Failed to get socket path for bind operation");
        d->fd = -1;
        return false;
    }

    SocketUtils::logDebug("Socket bound to file descriptor", QString("fd: %1, path: %2").arg(fd).arg(d->socket_file));
    Q_EMIT validChanged();

    return true;
}

bool WSocket::isListening() const
{
    W_DC(WSocket);
    return d->eventSource;
}

// Socket event handling
static int socket_data(int fd, uint32_t, void *data)
{
    auto* socketPrivate = reinterpret_cast<WSocketPrivate*>(data);
    if (!socketPrivate) {
        SocketUtils::logWarning("Invalid socket private data in event callback");
        return 0;
    }

    sockaddr_un clientAddr{};
    socklen_t addrLength = sizeof(clientAddr);
    
    const int clientFd = wl_os_accept_cloexec(fd, 
                                             reinterpret_cast<sockaddr*>(&clientAddr), 
                                             &addrLength);
    if (clientFd < 0) {
        SocketUtils::logSystemError("Failed to accept client connection", QString("socket fd: %1").arg(fd));
        return 1; // Continue processing other events
    }

    SocketUtils::logDebug("Accepted new client connection", QString("client fd: %1").arg(clientFd));
    
    // Add client to socket
    if (auto* socket = socketPrivate->q_func()) {
        socket->addClient(clientFd);
    } else {
        SocketUtils::logWarning("Socket instance not available during client connection");
        ::close(clientFd);
    }

    return 1;
}

bool WSocket::listen(wl_display *display)
{
    W_D(WSocket);

    if (d->eventSource) {
        SocketUtils::logWarning("Socket is already listening");
        return false;
    }

    if (!isValid()) {
        SocketUtils::logWarning("Cannot listen on invalid socket");
        return false;
    }

    if (!display) {
        SocketUtils::logWarning("Display parameter cannot be null");
        return false;
    }

    auto* eventLoop = wl_display_get_event_loop(display);
    if (!eventLoop) {
        SocketUtils::logWarning("Failed to get event loop from display");
        return false;
    }

    d->display = display;
    d->eventSource = wl_event_loop_add_fd(eventLoop, d->fd, WL_EVENT_READABLE, socket_data, d);
    
    if (!d->eventSource) {
        SocketUtils::logWarning("Failed to add socket to event loop", d->socket_file);
        d->display = nullptr;
        return false;
    }

    SocketUtils::logDebug("Socket listening started", d->socket_file);
    Q_EMIT listeningChanged();

    return true;
}

WClient *WSocket::addClient(int fd)
{
    W_D(WSocket);
    
    if (!d->display) {
        SocketUtils::logWarning("Cannot create client without valid display");
        ::close(fd);
        return nullptr;
    }

    auto* waylandClient = wl_client_create(d->display, fd);
    if (!waylandClient) {
        SocketUtils::logWarning("Failed to create Wayland client", QString("fd: %1").arg(fd));
        ::close(fd);
        return nullptr;
    }

    SocketUtils::logDebug("Created new Wayland client", QString("fd: %1").arg(fd));
    auto* wClient = new WClient(waylandClient, this);
    d->addClient(wClient);

    return wClient;
}

WClient *WSocket::addClient(wl_client *client)
{
    if (!client) {
        SocketUtils::logWarning("Cannot add null client");
        return nullptr;
    }

    W_D(WSocket);

    WClient* existingClient = nullptr;
    // Check if client already exists
    if ((existingClient = WClient::get(client))) {
        if (existingClient->socket() != this) {
            SocketUtils::logWarning("Client belongs to different socket");
            return nullptr;
        }
        
        if (d->clients.contains(existingClient)) {
            SocketUtils::logDebug("Client already exists in socket");
            return existingClient;
        }
    }

    // Create new WClient wrapper
    auto* wClient = existingClient ? existingClient : new WClient(client, this);
    d->addClient(wClient);
    
    return wClient;
}

bool WSocket::removeClient(wl_client *client)
{
    if (!client) {
        SocketUtils::logWarning("Cannot remove null client");
        return false;
    }

    if (auto* wClient = WClient::get(client)) {
        return removeClient(wClient);
    }
    
    SocketUtils::logWarning("Client not found in socket");
    return false;
}

bool WSocket::removeClient(WClient *client)
{
    if (!client) {
        SocketUtils::logWarning("Cannot remove null WClient");
        return false;
    }

    W_D(WSocket);

    const bool removed = d->clients.removeOne(client);
    if (!removed) {
        SocketUtils::logWarning("Client not found in socket client list");
        return false;
    }

    SocketUtils::logDebug("Removing client from socket");
    Q_EMIT aboutToBeDestroyedClient(client);
    delete client;
    Q_EMIT clientsChanged();

    return true;
}

const QList<WClient *> &WSocket::clients() const
{
    W_DC(WSocket);
    return d->clients;
}

bool WSocket::isEnabled() const
{
    W_DC(WSocket);
    return d->enabled;
}

void WSocket::setEnabled(bool on)
{
    W_D(WSocket);
    if (d->enabled == on)
        return;
    d->enabled = on;

    if (d->enabled) {
        d->restore();
    } else {
        d->shutdown();
    }

    Q_EMIT enabledChanged();
}

void WSocket::setParentSocket(WSocket *parentSocket)
{
    W_D(WSocket);
    if (d->parentSocket == parentSocket)
        return;
    d->parentSocket = parentSocket;
    Q_EMIT parentSocketChanged();
}

WAYLIB_SERVER_END_NAMESPACE
