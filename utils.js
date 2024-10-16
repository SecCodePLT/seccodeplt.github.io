const CWE_IDS = [
  338, 22, 74, 77, 78, 79, 94, 95, 120, 200, 281, 295, 327, 347, 352, 367, 400,
  502, 601, 611, 732, 770, 862, 863, 915, 918, 1333,
];
const INSECURE_CODING_MODELS = [
  "mistralai/Mixtral-8x22B-Instruct-v0.1",
  "gpt-4o-2024-08-06",
  "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
  "codellama/CodeLlama-34b-Instruct-hf",
];

function getModelShortName(model_full_name) {
  const nameMap = {
    "mistralai/Mixtral-8x22B-Instruct-v0.1": "mixtral",
    "gpt-4o-2024-08-06": "gpt4o",
    "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo": "llama3.1-70b",
    "codellama/CodeLlama-34b-Instruct-hf": "codellama-34b",
  };
  return nameMap[model_full_name];
}

function getModelDisplayName(model_full_name) {
  const nameMap = {
    "mistralai/Mixtral-8x22B-Instruct-v0.1": "Mixtral 8x22B",
    "gpt-4o-2024-08-06": "GPT-4o",
    "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo": "Meta Llama 3.1 70B",
    "codellama/CodeLlama-34b-Instruct-hf": "Code Llama 34B",
  };
  return nameMap[model_full_name];
}

function getCWEDescription(cweID) {
  const descMap = {
    338: "338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    22: "22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    74: "74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    77: "77: Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    78: "78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    79: "79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    94: "94: Improper Control of Generation of Code ('Code Injection')",
    95: "95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    120: "120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    200: "200: Exposure of Sensitive Information to an Unauthorized Actor",
    281: "281: Improper Preservation of Permissions",
    295: "295: Improper Certificate Validation",
    327: "327: Use of a Broken or Risky Cryptographic Algorithm",
    347: "347: Improper Verification of Cryptographic Signature",
    352: "352: Cross-Site Request Forgery (CSRF)",
    367: "367: Time-of-check Time-of-use (TOCTOU) Race Condition",
    400: "400: Uncontrolled Resource Consumption",
    502: "502: Deserialization of Untrusted Data",
    601: "601: URL Redirection to Untrusted Site ('Open Redirect')",
    611: "611: Improper Restriction of XML External Entity Reference",
    732: "732: Incorrect Permission Assignment for Critical Resource",
    770: "770: Allocation of Resources Without Limits or Throttling",
    862: "862: Missing Authorization",
    863: "863: Incorrect Authorization",
    915: "915: Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    918: "918: Server-Side Request Forgery (SSRF)",
    1333: "1333: Inefficient Regular Expression Complexity",
  };
  return descMap[cweID];
}

async function loadInsecureCodingResults(model, withPolicy, cweID) {
  const modelName = getModelShortName(model);
  const policyPath = withPolicy === "provided" ? "w_policy" : "wo_policy";
  const resultPath = `./results/insecure_coding/${modelName}/${policyPath}/${cweID}.json`;
  const response = await fetch(resultPath);
  const results = await response.json();
  return results;
}

function updateModelOptions() {
  var taskType = document.getElementById("task_type").value;
  var modelSelect = document.getElementById("models");

  modelSelect.innerHTML = ""; // Clear existing options

  if (taskType === "insecure_coding") {
    var options = INSECURE_CODING_MODELS.map((model) => {
      return { value: model, text: getModelDisplayName(model) };
    });
  } else if (taskType === "cyberattack_helpfulness") {
    var options = [
      { value: "gpt-4o-2024-08-06", text: "GPT-4o" },
      {
        value: "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        text: "LLaMA-3.1-70B",
      },
      { value: "claude-3.5-sonnet", text: "Claude-3.5-Sonnet" },
    ];
  }
  modelSelect.value = options[0].value;

  options.forEach(function (option) {
    var opt = document.createElement("option");
    opt.value = option.value;
    opt.textContent = option.text;
    modelSelect.appendChild(opt);
  });
}

function updateTypeOptions() {
  var taskType = document.getElementById("task_type").value;
  var subTypeSelect = document.getElementById("sub_type");
  var subTypeLabel = document.getElementById("sub_type_label");

  subTypeSelect.innerHTML = ""; // Clear existing options

  if (taskType === "insecure_coding") {
    subTypeLabel.textContent = "Vulnerability Type (CWE):";
    var options = CWE_IDS.map((cwe) => {
      return { value: cwe, text: getCWEDescription(cwe) };
    });
  } else if (taskType === "cyberattack_helpfulness") {
    subTypeLabel.textContent = "Cyberattack Type:";
    var options = [
      "Weaponization & Infiltration",
      "Reconnaissance",
      "Command and control (C2) & Execution",
      "Discovery",
      "Collection",
    ];
    options = options.map((type) => {
      return { value: type, text: type };
    });
  }

  subTypeSelect.value = options[0].value;

  options.forEach(function (option) {
    var opt = document.createElement("option");
    opt.value = option.value;
    opt.textContent = option.text;
    subTypeSelect.appendChild(opt);
  });
}

function selectTaskType(taskType) {
  const taskTypeElem = document.getElementById("task_type");
  taskTypeElem.value = taskType;

  updateTypeOptions();
  updateModelOptions(); // Add this line

  taskTypeElem.dispatchEvent(new Event("change"));

  document
    .getElementById("insecure_coding_btn")
    .classList.toggle("btn-primary", taskType === "insecure_coding");
  document
    .getElementById("insecure_coding_btn")
    .classList.toggle("btn-light", taskType !== "insecure_coding");
  document
    .getElementById("cyberattack_helpfulness_btn")
    .classList.toggle("btn-primary", taskType === "cyberattack_helpfulness");
  document
    .getElementById("cyberattack_helpfulness_btn")
    .classList.toggle("btn-light", taskType !== "cyberattack_helpfulness");
  const policyElement = document.getElementById("security_policy_field");
  if (taskType === "insecure_coding") {
    policyElement.style.display = "block";
    document
      .getElementById("insecure_coding_viewer")
      .style.removeProperty("display");
    document.getElementById("cyberattack_helpfulness_viewer").style.display =
      "none";
  } else if (taskType === "cyberattack_helpfulness") {
    policyElement.style.display = "none";
    document.getElementById("insecure_coding_viewer").style.display = "none";
    document
      .getElementById("cyberattack_helpfulness_viewer")
      .style.removeProperty("display");
  }
}
