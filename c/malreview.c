#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <ctime>
#include <filesystem>
#include <cstdlib>
#include <cstdio>
#include <array>

namespace fs = std::filesystem;

void show_help() {
    std::cout << "Usage: malanalyze -f <filename>" << std::endl;
    exit(1);
}

std::string current_utc_time() {
    std::time_t now = std::time(nullptr);
    std::tm *gmtm = std::gmtime(&now);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtm);
    return std::string(buf);
}

void log_and_run(const std::string &cmd, const std::string &output_file, const std::string &log_file) {
    std::string timestamp = current_utc_time();
    std::ofstream log(log_file, std::ios::app);
    log << "[" << timestamp << "] Running command: " << cmd << std::endl;

    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");

    std::ofstream output(output_file);
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        output << buffer.data();
        log << buffer.data();
    }
}

void resolve_full_path(const std::string &filename, std::string &full_path) {
    full_path = fs::canonical(filename);
    if (!fs::exists(full_path)) {
        std::cerr << "Error: File " << filename << " not found." << std::endl;
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        show_help();
    }
    if (std::string(argv[1]) != "-f") {
        show_help();
    }

    std::string fn = argv[2];
    std::string full_path;
    resolve_full_path(fn, full_path);

    std::string pwd = fs::current_path().string();
    std::string evidence_store = pwd + "/evidence";
    fs::create_directories(evidence_store);

    std::string log_file = evidence_store + "/log.txt";

    std::cout << "[ ] Creating evidence store at " << evidence_store << "." << std::endl;
    std::cout << "[ ] Collecting data on " << full_path << " now, please wait." << std::endl;

    log_and_run("file " + full_path, evidence_store + "/file.txt", log_file);
    log_and_run("sha1sum " + full_path, evidence_store + "/sha1hash.txt", log_file);
    log_and_run("readelf -a " + full_path, evidence_store + "/readelf.txt", log_file);
    log_and_run("objdump -d " + full_path, evidence_store + "/objdump.txt", log_file);
    log_and_run("strings -n8 " + full_path, evidence_store + "/strings.txt", log_file);
    log_and_run("ldd " + full_path, evidence_store + "/ldd.txt", log_file);

    std::cout << "[ ] Static analysis complete." << std::endl;

    std::string sha256_cmd = "sha256sum " + log_file + " | awk '{ print $1 }'";
    std::array<char, 65> buffer;
    std::shared_ptr<FILE> pipe(popen(sha256_cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    std::string hash;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        hash += buffer.data();
    }

    std::cout << "[ ] Evidence is stored in " << evidence_store << " and the log file is at " << log_file << "." << std::endl;
    std::cout << "[*] The SHA256 hash of the log file is " << hash << std::endl;

    return 0;
}
