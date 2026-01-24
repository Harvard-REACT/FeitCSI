#ifndef LOGGER_H
#define LOGGER_H

#include <gtkmm.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

enum Level { debug, error, warning, info };

class Logger {
    static const char* levelToStr(Level l) {
        switch (l) {
            case debug:
                return "DEBUG";
            case info:
                return "INFO";
            case warning:
                return "WARN";
            case error:
                return "ERROR";
        }
        return "UNK";
    }

    static const char* baseName(const char* path) {
        if (!path)
            return "";
        const char* s1 = std::strrchr(path, '/');
        const char* s2 = std::strrchr(path, '\\');
        const char* s = (s1 && s2) ? (s1 > s2 ? s1 : s2) : (s1 ? s1 : s2);
        return s ? s + 1 : path;
    }

   public:
    inline static Level debugLevel = info;
    inline static Glib::RefPtr<Gtk::TextBuffer> guiOutput;

    inline static Logger* INSTANCE = nullptr;

    static Logger& log(Level n,
                       bool persist = false,
                       const char* file = nullptr,
                       int line = 0,
                       const char* func = nullptr) {
        if (INSTANCE && !persist) {
            delete INSTANCE;
            INSTANCE = nullptr;
        }

        if (!INSTANCE) {
            INSTANCE = new Logger();

            auto now = std::chrono::system_clock::now();
            auto mcs =
                std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) %
                1000000;
            auto timer = std::chrono::system_clock::to_time_t(now);
            std::tm bt = *std::localtime(&timer);

            std::ostringstream oss;
            oss << "[";
            oss << std::put_time(&bt, "%H:%M:%S");  // HH:MM:SS
            oss << '.' << std::setfill('0') << std::setw(6) << mcs.count();
            oss << "] ";

            oss << "[" << levelToStr(n) << "] ";

            if (file) {
                oss << "(" << baseName(file) << ":" << line;
                if (func)
                    oss << " " << func;
                oss << ") ";
            }

            *INSTANCE << oss.str();
        }

        Logger::debugLevel = n;  // keeping your original behavior
        return *INSTANCE;
    }

    static gboolean guiLog(void* data) {
        std::string* msg = static_cast<std::string*>(data);
        Logger::guiOutput->insert_at_cursor(*msg);
        delete msg;
        return G_SOURCE_REMOVE;
    }

    template <class T>
    Logger& operator<<(const T& v) {
        if (Logger::guiOutput) {
            std::stringstream ss;
            ss << v;
            std::cerr << ss.str();
            auto* d = new std::string(ss.str());
            gdk_threads_add_idle(guiLog, static_cast<void*>(d));
        } else {
            std::cerr << v;
        }

        return *this;
    }
};

#define LOG(LVL) Logger::log((LVL), false, __FILE__, __LINE__, __func__)
#define LOG_P(LVL) Logger::log((LVL), true, __FILE__, __LINE__, __func__)

#define LOG_INFO LOG(info)
#define LOG_WARN LOG(warning)
#define LOG_ERR LOG(error)
#define LOG_DEBUG LOG(debug)

#endif
