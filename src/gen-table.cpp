// ---------------------------------------------------------------------------
//  gen-table -- preprocessing program: build a rainbow table for one password
//  length and write it to disk.
//
//  Usage:
//      gen-table L m t table_id out_file [threads]
//
//        L         password length (6..10)
//        m         number of chains to generate
//        t         chain length (number of hash/reduce steps per chain)
//        table_id  reduction-family id (use distinct ids for several tables of
//                  the same length to raise the success rate)
//        out_file  destination file for the table
//        threads   worker threads (default: hardware concurrency)
//
//  Cost / size guide (per table):
//        hash evaluations  ~= m * t
//        disk / RAM        ~= m * 16 bytes  (before endpoint de-duplication)
//
//  Building several tables (different table_id) for the same length multiplies
//  the cost but sharply increases the probability of cracking a given hash.
// ---------------------------------------------------------------------------

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>

#include "rainbow.hpp"
#include "misc/threadpool.hpp"

using namespace rainbow;

int main(int argc, char* argv[])
{
    if (argc != 6 && argc != 7)
    {
        std::cerr <<
            "Usage: gen-table L m t table_id out_file [threads]\n"
            "  L         password length (6..10)\n"
            "  m         number of chains\n"
            "  t         chain length\n"
            "  table_id  reduction-family id (0,1,2,... for several tables)\n"
            "  out_file  output table file\n"
            "  threads   worker threads (default: all cores)\n";
        return 1;
    }

    const int      L        = std::stoi(argv[1]);
    const uint64_t m        = std::stoull(argv[2]);
    const uint64_t t        = std::stoull(argv[3]);
    const uint32_t table_id = uint32_t(std::stoul(argv[4]));
    const std::string out   = argv[5];
    unsigned threads = (argc == 7) ? unsigned(std::stoul(argv[6]))
                                   : std::thread::hardware_concurrency();
    if (threads == 0) threads = 1;

    if (L < MIN_LEN || L > MAX_LEN)
    {
        std::cerr << "L must be between " << MIN_LEN << " and " << MAX_LEN << '\n';
        return 1;
    }

    std::cerr << "  SHA-256   : "
              << (rainbow::shani_enabled() ? "hardware-accelerated (SHA extensions)"
                                           : "scalar (no SHA extensions on this CPU)")
              << '\n';

    const uint64_t N = keyspace(L);

    // Starting points are the sequential indices 0..m-1: they are distinct and
    // free to produce. If m exceeds the key space, cap it (full coverage).
    const uint64_t chain_count = (m < N) ? m : N;

    std::cerr << "Building rainbow table\n"
              << "  length    : " << L << "  (key space 62^" << L << " = " << N << ")\n"
              << "  chains    : " << chain_count << "\n"
              << "  chain len : " << t << "\n"
              << "  table id  : " << table_id << "\n"
              << "  threads   : " << threads << "\n"
              << "  est. hash : " << (chain_count * t) << " SHA-256 evaluations\n"
              << "  raw size  : ~" << (chain_count * sizeof(Chain)) / (1024 * 1024)
              << " MiB (before de-duplication)\n" << std::flush;

    std::vector<Chain> chains(chain_count);

    const auto start_time = std::chrono::steady_clock::now();
    std::atomic<uint64_t> done{0};

    {
        ThreadPool pool(threads);

        // Split the work into a handful of blocks per thread for good balance.
        const uint64_t block = 1u << 16;        // 65536 chains per task
        std::vector<std::future<void>> futures;

        for (uint64_t begin = 0; begin < chain_count; begin += block)
        {
            const uint64_t end = std::min(begin + block, chain_count);
            futures.push_back(pool.enqueue(
                [&, begin, end]()
                {
                    for (uint64_t i = begin; i < end; ++i)
                    {
                        chains[i].start = i;
                        chains[i].end   = chain_endpoint(i, t, L, table_id, N);
                    }
                    done.fetch_add(end - begin, std::memory_order_relaxed);
                }));
        }

        // Progress reporting while the pool crunches.
        while (true)
        {
            uint64_t d = done.load(std::memory_order_relaxed);
            std::cerr << "\r  progress  : " << d << " / " << chain_count
                      << " chains   " << std::flush;
            if (d >= chain_count) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        for (auto& f : futures) f.get();   // propagate exceptions, if any
    }
    std::cerr << '\n';

    const auto gen_time = std::chrono::steady_clock::now();

    write_table(out, uint32_t(L), table_id, t, N, chains);

    const auto end_time = std::chrono::steady_clock::now();
    auto secs = [](auto a, auto b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count() / 1000.0;
    };

    std::cerr << "  kept      : " << chains.size()
              << " distinct-endpoint chains ("
              << (chains.size() * sizeof(Chain)) / (1024 * 1024) << " MiB)\n"
              << "  generate  : " << secs(start_time, gen_time) << " s\n"
              << "  write     : " << secs(gen_time, end_time) << " s\n"
              << "  file      : " << out << "\n"
              << "Done.\n";
    return 0;
}
