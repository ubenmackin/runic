// Refetch intervals (milliseconds)
export const REFETCH_INTERVALS = {
  DASHBOARD_PEERS: 15000,
  DASHBOARD_LOGS: 60000,
  PEERS_PAGE: 30000,
};

// OS and architecture options for peer configuration
export const OS_OPTIONS = [
  { value: "ubuntu", label: "Ubuntu" },
  { value: "opensuse", label: "openSUSE" },
  { value: "raspbian", label: "Raspbian" },
  { value: "armbian", label: "Armbian" },
  { value: "ios", label: "iOS" },
  { value: "ipados", label: "iPadOS" },
  { value: "macos", label: "macOS" },
  { value: "tvos", label: "tvOS" },
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Generic Linux" },
  { value: "other", label: "Other" },
];

export const ARCH_OPTIONS = [
  { value: "amd64", label: "amd64" },
  { value: "arm64", label: "arm64" },
  { value: "arm", label: "arm" },
  { value: "other", label: "Other" },
];
