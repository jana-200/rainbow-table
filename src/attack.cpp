// ---------------------------------------------------------------------------
//  attack -- exploit one or more rainbow tables to crack SHA-256 hashes.
//
//  Usage:
//      attack in_hashes out_passwords table1 [table2 ...] [--threads n]
//
//        in_hashes       input file, one lowercase-hex SHA-256 per line
//                        (last line blank, as produced by gen-passwd)
//        out_passwords   output file, one cracked password per line, in the
//                        same order as the input; uncracked hashes become a
//                        line containing only '?'  (last line blank)
//        tableK          rainbow table files produced by gen-table
//        --threads n     worker threads (default: all cores)
//
//  Each input hash is processed independently, so the hashes are spread over
//  the thread pool. For a given hash we try every table (shorter passwords
//  first) until one cracks it.
// ---------------------------------------------------------------------------

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>

#include "rainbow.hpp"
#include "misc/threadpool.hpp"

using namespace rainbow;

int main(int argc, char* argv[])
{
    std::vector<std::string> table_paths;
    std::string in_path, out_path;
    unsigned threads = std::thread::hardware_concurrency();

    // ---- argument parsing ------------------------------------------------
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--threads" && i + 1 < argc)
            threads = unsigned(std::stoul(argv[++i]));
        else
            pos.push_back(a);
    }
    if (pos.size() < 3)
    {
        std::cerr <<
            "Usage: attack in_hashes out_passwords table1 [table2 ...] [--threads n]\n"
            "  in_hashes      input file: one lowercase-hex SHA-256 per line\n"
            "  out_passwords  output file: one password per line ('?' if uncracked)\n"
            "  tableK         rainbow table files produced by gen-table\n"
            "  --threads n    worker threads (default: all cores)\n";
        return 1;
    }
    if (threads == 0) threads = 1;

    in_path  = pos[0];
    out_path = pos[1];
    for (size_t i = 2; i < pos.size(); ++i)
        table_paths.push_back(pos[i]);

    std::cerr << "SHA-256: "
              << (rainbow::shani_enabled() ? "hardware-accelerated (SHA extensions)"
                                           : "scalar (no SHA extensions on this CPU)")
              << '\n';

    // ---- load tables -----------------------------------------------------
    std::cerr << "Loading " << table_paths.size() << " table(s)...\n";
    std::vector<Table> tables;
    tables.reserve(table_paths.size());
    uint64_t mem = 0;
    for (const auto& p : table_paths)
    {
        Table tb = load_table(p);
        mem += tb.memory_bytes();
        std::cerr << "  " << p << "  (L=" << tb.length
                  << ", id=" << tb.table_id
                  << ", t=" << tb.t
                  << ", chains=" << tb.chains.size() << ")\n";
        tables.push_back(std::move(tb));
    }
    std::cerr << "  total RAM for tables: ~"
              << mem / (1024 * 1024) << " MiB\n";

    // Try shorter passwords first (cheaper and usually more likely).
    std::sort(tables.begin(), tables.end(),
              [](const Table& a, const Table& b)
              {
                  if (a.length != b.length) return a.length < b.length;
                  return a.table_id < b.table_id;
              });

    // ---- read hashes -----------------------------------------------------
    std::ifstream fin(in_path);
    if (!fin)
    {
        std::cerr << "cannot open input hash file: " << in_path << '\n';
        return 1;
    }
    std::vector<std::string> hex_lines;
    std::string line;
    while (std::getline(fin, line))
    {
        // tolerate trailing whitespace / CR
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '
                                 || line.back() == '\t'))
            line.pop_back();
        if (line.empty())
            continue;                       // skip blank lines (incl. final one)
        hex_lines.push_back(line);
    }
    fin.close();

    const size_t n = hex_lines.size();
    std::cerr << "Cracking " << n << " hash(es) with "
              << threads << " thread(s)...\n";

    std::vector<std::string> results(n);     // "" means not cracked yet
    std::atomic<uint64_t> cracked{0};
    std::atomic<uint64_t> done{0};

    {
        ThreadPool pool(threads);
        std::vector<std::future<void>> futures;
        futures.reserve(n);

        for (size_t i = 0; i < n; ++i)
        {
            futures.push_back(pool.enqueue(
                [&, i]()
                {
                    uint8_t target[SHA256::HashBytes];
                    if (hex_to_digest(hex_lines[i], target))
                    {
                        std::string pwd;
                        for (const Table& tb : tables)
                        {
                            if (crack_with_table(target, tb, pwd))
                            {
                                results[i] = pwd;
                                cracked.fetch_add(1, std::memory_order_relaxed);
                                break;
                            }
                        }
                    }
                    done.fetch_add(1, std::memory_order_relaxed);
                }));
        }

        while (true)
        {
            uint64_t d = done.load(std::memory_order_relaxed);
            std::cerr << "\r  progress: " << d << " / " << n
                      << "   cracked: " << cracked.load(std::memory_order_relaxed)
                      << "    " << std::flush;
            if (d >= n) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        for (auto& f : futures) f.get();
    }
    std::cerr << '\n';

    // ---- write output ----------------------------------------------------
    std::ofstream fout(out_path);
    if (!fout)
    {
        std::cerr << "cannot open output file: " << out_path << '\n';
        return 1;
    }
    for (size_t i = 0; i < n; ++i)
        fout << (results[i].empty() ? std::string("?") : results[i]) << '\n';
    // The loop above already leaves the file ending on a newline, i.e. a blank
    // final line, as required by the statement.
    fout.close();

    std::cerr << "Cracked " << cracked.load() << " / " << n << " ("
              << (n ? (100.0 * double(cracked.load()) / double(n)) : 0.0)
              << "%). Output written to " << out_path << '\n';
    return 0;
}
