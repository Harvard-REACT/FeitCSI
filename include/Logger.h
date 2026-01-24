#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include "gtkmm/textbuffer.h"

enum Level { debug, info, warning, error };

class Logger {
   public:
    inline static std::mutex sinkMutex;
    inline static Glib::RefPtr<Gtk::TextBuffer> guiOutput;

    static const char* levelToStr(Level l) {
        switch (l) {
            case debug:
                return "DEBUG";
            case info:
                return "INFO";
            case warning:
                return "WARNING";
            case error:
                return "ERROR";
            default:
                return "UNKNOWN";
        }
    }
    static const char* basename(const char* path) {
        const char* base = strrchr(path, '/');
        return base ? base + 1 : path;
    }

    static void write(std::string msg) {
        // Prevent interleaving of whole messages on stderr
        {
            std::lock_guard<std::mutex> lock(sinkMutex);
            std::cerr << msg;
        }

        // GUI: schedule on GTK main loop (don’t touch TextBuffer from worker threads)
        if (guiOutput) {
            // Capture a strong ref + message so guiOutput can’t disappear under us
            struct Payload {
                Glib::RefPtr<Gtk::TextBuffer> buf;
                std::string msg;
            };
            auto* p = new Payload{guiOutput, std::move(msg)};

            g_main_context_invoke(
                nullptr,
                [](gpointer data) -> gboolean {
                    auto* p = static_cast<Payload*>(data);
                    if (p->buf)
                        p->buf->insert_at_cursor(p->msg);
                    delete p;
                    return G_SOURCE_REMOVE;
                },
                p);
        }
    }

    class Line {
       public:
        Line(Level n, const char* file, int line, const char* func) {
            // Use localtime_r for thread safety
            auto now = std::chrono::system_clock::now();
            auto us =
                std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) %
                1000000;
            auto t = std::chrono::system_clock::to_time_t(now);

            std::tm bt{};
            localtime_r(&t, &bt);

            oss_ << "[" << std::put_time(&bt, "%H:%M:%S") << "." << std::setfill('0')
                 << std::setw(6) << us.count() << "] " << "[" << Logger::levelToStr(n) << "] ";

            if (file) {
                oss_ << "(" << Logger::basename(file) << ":" << line;
                if (func)
                    oss_ << " " << func;
                oss_ << ") ";
            }
        }

        ~Line() {
            // Ensure newline policy however you like:
            oss_ << "\n";
            Logger::write(oss_.str());
        }

        template <class T>
        Line& operator<<(const T& v) {
            oss_ << v;
            return *this;
        }

       private:
        std::ostringstream oss_;
    };
};

#define LOG(LVL) Logger::Line((LVL), __FILE__, __LINE__, __func__)
#define LOG_INFO LOG(info)
#define LOG_WARN LOG(warning)
#define LOG_ERR LOG(error)
#define LOG_DEBUG LOG(debug)
