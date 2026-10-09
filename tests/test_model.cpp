#include "test_util.hpp"

#include "vnm/model.hpp"

int main() {
    using namespace vnm;

    Host down;
    down.status = HostStatus::Down;
    CHECK(evaluate_risk(down) == RiskLevel::Offline);

    Host quiet;
    quiet.status = HostStatus::Up;
    CHECK(evaluate_risk(quiet) == RiskLevel::Safe);

    Host exposing_ssh;
    exposing_ssh.status = HostStatus::Up;
    exposing_ssh.ports.push_back(Port{22, "tcp", "open", "ssh", "OpenSSH", "9.0", ""});
    CHECK(evaluate_risk(exposing_ssh) == RiskLevel::Warning);
    CHECK(exposing_ssh.has_open_port());
    CHECK(exposing_ssh.open_port_count() == 1);

    Host telnet;
    telnet.status = HostStatus::Up;
    telnet.ports.push_back(Port{23, "tcp", "open", "telnet", "", "", ""});
    CHECK(evaluate_risk(telnet) == RiskLevel::Critical);

    Port closed{80, "tcp", "closed", "http", "", "", ""};
    CHECK(closed.describe() == "80/tcp closed http");

    Port svc{22, "tcp", "open", "ssh", "OpenSSH", "8.9p1", ""};
    CHECK(svc.describe() == "22/tcp open ssh (OpenSSH 8.9p1)");

    CHECK(std::string(to_string(RiskLevel::Critical)) == "critical");
    CHECK(risk_color(RiskLevel::Safe) == 0x2ECC71);

    // Responsiveness: real discovery reasons count, assumed ones do not.
    Host real;
    real.status = HostStatus::Up;
    real.status_reason = "syn-ack";
    CHECK(real.is_responsive());

    Host assumed;
    assumed.status = HostStatus::Up;
    assumed.status_reason = "user-set";
    CHECK(!assumed.is_responsive());
    CHECK(!assumed.has_open_port());

    assumed.ports.push_back(Port{22, "tcp", "open", "ssh", "", "", ""});
    CHECK(assumed.is_responsive()); // open port wins over the assumed reason

    Host no_reason;
    no_reason.status = HostStatus::Up;
    CHECK(no_reason.is_responsive()); // hand-built host without a reason

    return vnmtest::summary("model");
}
