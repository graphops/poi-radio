const { exec } = require("child_process");
const fs = require("fs");
const process = require("process");

let childProcesses = [];

process.on("SIGINT", cleanUp);

if (!fs.existsSync("logs")) {
  fs.mkdirSync("logs");
}

let numTotalTests = 0;
let numSuccessTests = 0;
let numFailTests = 0;
let namesOfFailedTests = [];

function cleanUp() {
  console.log("Cleaning up child processes...");
  childProcesses.forEach((proc) => proc.kill());
  console.log("Exiting...");
  process.exit();
}

function printSummaryReport() {
  let endTime = process.uptime();
  let duration = endTime;
  let durationMinutes = Math.floor(duration / 60);
  let durationSeconds = Math.floor(duration % 60);

  console.log("Summary Report:");
  console.log(`
-------------------------------------
Total Tests Run: ${numTotalTests}
Successful Tests: ${numSuccessTests}
Failed Tests: ${numFailTests}
Test Suite Duration: ${durationMinutes}m ${durationSeconds}s
-------------------------------------
`);

  if (numFailTests > 0) {
    console.log("The following tests failed:");
    namesOfFailedTests.forEach((name) => console.log(name));
    dumpFailedTestsLogs();
    process.exit(1);
  }

  process.exit(0);
}

async function runTest(testName, testPath, testEnv) {
  console.log(`Running test: ${testName}`);
  numTotalTests++;

  let options = {
    env: Object.assign(
      {
        RUST_BACKTRACE: 1,
        RUST_LOG:
          "off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace",
      },
      process.env
    ),
    shell: true,
  };

  let testCommand = `cargo test --lib -- ${testPath} "${testEnv}" > "logs/${testName}_logs.log" 2>&1`;

  // If it's a basic_instance test, run it in a Docker container
  if (testName.startsWith("run_basic_instance")) {
    testCommand = `docker build -t test_image . && docker run -e TEST_TO_RUN=${testPath} test_image`;
  }

  return new Promise((resolve, reject) => {
    let proc = exec(testCommand, options, (error, stdout, stderr) => {
      if (error) {
        console.log(`${testName} - ✗`);
        numFailTests++;
        namesOfFailedTests.push(testName);
        reject(error);
      } else {
        console.log(`${testName} - ✓`);
        numSuccessTests++;
        resolve();
      }
    });

    if (testName.startsWith("run_basic_instance")) {
      childProcesses.push(proc);
    }
  });
}

function dumpFailedTestsLogs() {
  console.log("Dumping failed tests logs to logs/failed_tests_logs.log");
  fs.unlinkSync("logs/failed_tests_logs.log", { force: true });
  namesOfFailedTests.forEach((testName) => {
    let logContent = fs.readFileSync(`logs/${testName}_logs.log`);
    fs.appendFileSync(
      "logs/failed_tests_logs.log",
      `===== ${testName} =====\n`
    );
    fs.appendFileSync("logs/failed_tests_logs.log", logContent);
    fs.appendFileSync("logs/failed_tests_logs.log", "\n\n");
  });
}

async function isDockerReady() {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const timeout = 30 * 60 * 1000; // 30 minutes

    const checkContainer = setInterval(() => {
      if (Date.now() - startTime > timeout) {
        clearInterval(checkContainer);
        reject(new Error("Timeout waiting for Docker container"));
      }

      exec("docker ps -a | grep test_image", (error, stdout, stderr) => {
        if (stdout.includes("test_image")) {
          clearInterval(checkContainer);
          resolve();
        }
      });
    }, 1000);
  });
}

async function runAllTests() {
  // Start 5 instances of run_basic_instance in the background
  for (let i = 0; i < 5; i++) {
    runTest(
      `run_basic_instance_${i + 1}`,
      "integration_tests::setup::basic::tests::run_basic_instance",
      "RUST_LOG=trace"
    );
  }

  // Wait for Docker containers to be ready
  try {
    await isDockerReady();
  } catch (error) {
    console.error(`Error waiting for Docker: ${error}`);
    process.exit(1);
  }

  try {
    await runTest(
      "simple_tests",
      "integration_tests::checks::simple_tests::tests::run_simple_tests",
      "RUST_LOG=trace"
    );
    await runTest(
      "invalid_messages",
      "integration_tests::checks::invalid_messages::tests::test_invalid_messages",
      "RUST_LOG=trace"
    );
    await runTest(
      "invalid_sender",
      "integration_tests::checks::invalid_sender::tests::test_invalid_sender_check",
      "RUST_LOG=trace"
    );
  } catch (error) {
    console.error(`Error running tests: ${error}`);
  } finally {
    printSummaryReport();
  }
}

runAllTests();
