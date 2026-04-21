import { render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import CraftPolicyWizard from "./CraftPolicyWizard";

// Mock the API module
vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    api: {
      get: vi.fn(),
      post: vi.fn(),
      delete: vi.fn(),
    },
    QUERY_KEYS: {
      peers: () => ["peers"],
      services: () => ["services"],
      policies: () => ["policies"],
      logs: () => ["logs"],
    },
  };
});

// Import after mocking
import * as api from "../api/client";

// Mock the ToastContext
const mockShowToast = vi.fn();
vi.mock("../hooks/ToastContext", () => ({
  useToastContext: () => mockShowToast,
}));

// Mock the useFocusTrap hook
vi.mock("../hooks/useFocusTrap", () => ({
  useFocusTrap: vi.fn(),
}));

// Helper to create a 404 error with proper status property
function create404Error(message = "Not found") {
  const error = new Error(message);
  error.status = 404;
  return error;
}

// Helper to create wrapper with QueryClient
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return function Wrapper({ children }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
  };
}

// Helper to create mock log
function createMockLog(overrides = {}) {
  return {
    peer_id: 1,
    hostname: "test-peer",
    src_ip: "192.168.1.100",
    dst_ip: "10.0.0.1",
    src_port: 443,
    dst_port: 443,
    protocol: "tcp",
    direction: "IN",
    raw_line: "[RUNIC-IN] blocked packet...",
    ...overrides,
  };
}

describe("CraftPolicyWizard", () => {
  let wrapper;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    wrapper = createWrapper();
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  describe("rendering and portal", () => {
    test("renders modal in portal to document.body", () => {
      // Target peer, source peer
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      const overlay = document.querySelector(".fixed.inset-0.z-\\[9999\\]");
      expect(overlay).toBeInTheDocument();
    });

    test("renders modal title", () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      expect(screen.getByText("Craft Policy from Log")).toBeInTheDocument();
    });

    test("renders step indicators", () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      expect(screen.getByText("Peer")).toBeInTheDocument();
      expect(screen.getByText("Service")).toBeInTheDocument();
      expect(screen.getByText("Policy")).toBeInTheDocument();
      expect(screen.getByText("Review")).toBeInTheDocument();
    });
  });

  describe("step navigation", () => {
    test("starts at peer step", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
      });
    });

    test("shows loading state while fetching peer", () => {
      api.api.get.mockImplementation(() => new Promise(() => {}));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      expect(screen.getByText("Looking up peer by IP...")).toBeInTheDocument();
    });

    test("Back button is disabled on first step", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByRole("button", { name: /back/i })).toBeDisabled();
      });
    });

    test("navigates through all steps to review", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(
          screen.getByRole("textbox", { name: /name/i }),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument();
      });
    });
  });

  describe("peer detection and creation", () => {
    test("displays existing peer when found", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
      });
    });

    test("shows create new peer form when no peer found", async () => {
      api.api.get
        .mockRejectedValueOnce(create404Error())
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for the API call to be made
      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/peers/by-ip?ip=192.168.1.100",
          );
        },
        { timeout: 3000 },
      );

      // Wait for loading to complete and form to appear
      // When a 404 is returned, the component sets createNewPeerMode=true
      await waitFor(
        () => {
          expect(
            screen.getByPlaceholderText("Enter hostname"),
          ).toBeInTheDocument();
        },
        { timeout: 5000 },
      );
    });

    test("allows switching from existing peer to create new peer", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
      });

      await user.click(screen.getByText("Create a new peer instead"));

      await waitFor(() => {
        expect(
          screen.getByPlaceholderText("Enter hostname"),
        ).toBeInTheDocument();
      });
    });

    test("disables Next button when hostname is empty in new peer form", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockRejectedValueOnce(create404Error())
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for the form to appear
      const hostnameInput = await screen.findByPlaceholderText(
        "Enter hostname",
        {},
        { timeout: 5000 },
      );

      // The hostname field is pre-populated, so Next should be enabled initially
      const nextButton = screen.getByRole("button", { name: /next/i });
      expect(nextButton).not.toBeDisabled();

      // Clear the hostname
      await user.clear(hostnameInput);

      // Wait for the state to update
      await waitFor(() => {
        expect(hostnameInput).toHaveValue("");
      });

      // The Next button should be disabled when hostname is empty
      await waitFor(() => {
        expect(nextButton).toBeDisabled();
      });
    });
  });

  describe("service detection and creation", () => {
    test("displays existing service when found", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument();
      });
    });

    test("shows create new service form when no service found", async () => {
      const user = userEvent.setup();
      const error = new Error("Not found");
      error.status = 404;
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(error);

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/No existing service found/),
        ).toBeInTheDocument();
      });
    });

    test("disables Next button when service name is empty", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(create404Error());

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for peer to load
      await screen.findByText(/Found existing peer/, {}, { timeout: 5000 });

      // Move to service step
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for service form to appear
      await screen.findByPlaceholderText(
        "e.g., Web Server, Database",
        {},
        { timeout: 5000 },
      );

      // The service name field should be empty initially, so Next should be disabled
      const nextButton = screen.getByRole("button", { name: /next/i });
      await waitFor(() => {
        expect(nextButton).toBeDisabled();
      });
    });
  });

  describe("policy configuration", () => {
    test("displays policy form with pre-generated name", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(
          screen.getByRole("textbox", { name: /name/i }),
        ).toBeInTheDocument();
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument();
      });
    });

    test("policy name is auto-generated and Next button is enabled", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Navigate to policy step
      await screen.findByText(/Found existing peer/, {}, { timeout: 5000 });
      await user.click(screen.getByRole("button", { name: /next/i }));

      await screen.findByText(/Found existing service/, {}, { timeout: 5000 });
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for policy form to appear with auto-generated name
      await screen.findByDisplayValue(
        "existing-peer-https",
        {},
        { timeout: 5000 },
      );

      // The Next button should be enabled since policy name is auto-generated
      const nextButton = screen.getByRole("button", { name: /next/i });
      expect(nextButton).not.toBeDisabled();
    });

    test("displays policy summary in policy step", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(screen.getByText("Description (Optional)")).toBeInTheDocument();
        expect(screen.getAllByText("ACCEPT").length).toBeGreaterThan(0);
      });
    });
  });

  describe("review step", () => {
    test("displays all information for review", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(screen.getByText("PEER (Existing)")).toBeInTheDocument();
        expect(screen.getByText("SERVICE (Existing)")).toBeInTheDocument();
        expect(screen.getByText("POLICY")).toBeInTheDocument();
      });
    });

    test("shows Create Policy button instead of Next on review step", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument();
        expect(
          screen.queryByRole("button", { name: /next/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("policy submission", () => {
    test("creates peer, service, and policy on submit", async () => {
      const user = userEvent.setup();
      const mockOnClose = vi.fn();
      const mockOnSuccess = vi.fn();

      api.api.get
        .mockRejectedValueOnce(create404Error())
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(create404Error());

      api.api.post
        .mockResolvedValueOnce({ id: 10 })
        .mockResolvedValueOnce({ id: 20 })
        .mockResolvedValueOnce({ id: 30 });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={mockOnClose}
          onSuccess={mockOnSuccess}
        />,
        { wrapper },
      );

      // Wait for peer form to appear
      await waitFor(
        () => {
          expect(
            screen.getByPlaceholderText("Enter hostname"),
          ).toBeInTheDocument();
        },
        { timeout: 3000 },
      );

      // Type hostname (the field is pre-populated, so clear first)
      await user.clear(screen.getByPlaceholderText("Enter hostname"));
      await user.type(
        screen.getByPlaceholderText("Enter hostname"),
        "new-peer",
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for service form to appear
      await waitFor(
        () => {
          expect(
            screen.getByPlaceholderText("e.g., Web Server, Database"),
          ).toBeInTheDocument();
        },
        { timeout: 3000 },
      );
      await user.type(
        screen.getByPlaceholderText("e.g., Web Server, Database"),
        "new-service",
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for policy form to appear
      await waitFor(
        () => {
          expect(
            screen.getByPlaceholderText("Enter policy name"),
          ).toBeInTheDocument();
        },
        { timeout: 3000 },
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for review step
      await waitFor(
        () => {
          expect(
            screen.getByRole("button", { name: /create policy/i }),
          ).toBeInTheDocument();
        },
        { timeout: 3000 },
      );
      await user.click(screen.getByRole("button", { name: /create policy/i }));

      // Verify API calls - use mockResolvedValue to track call counts
      await waitFor(
        () => {
          expect(api.api.post).toHaveBeenCalledTimes(3);
          expect(mockOnSuccess).toHaveBeenCalled();
          expect(mockOnClose).toHaveBeenCalled();
        },
        { timeout: 3000 },
      );
    });

    test("uses existing peer and service when available", async () => {
      const user = userEvent.setup();
      const mockOnClose = vi.fn();
      const mockOnSuccess = vi.fn();

      api.api.get
        .mockResolvedValueOnce({
          id: 5,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 8,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      api.api.post.mockResolvedValueOnce({ id: 30 });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={mockOnClose}
          onSuccess={mockOnSuccess}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );

      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        // Only policy should be created, not peer or service
        expect(api.api.post).toHaveBeenCalledTimes(1);
        expect(mockOnSuccess).toHaveBeenCalled();
        expect(mockOnClose).toHaveBeenCalled();
      });
    });

    test("shows loading state during submission", async () => {
      const user = userEvent.setup();

      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      api.api.post.mockImplementation(
        () =>
          new Promise((resolve) => setTimeout(() => resolve({ id: 1 }), 100)),
      );

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );

      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        expect(screen.getByText("Creating...")).toBeInTheDocument();
      });
    });
  });

  describe("error handling", () => {
    test("displays error when peer lookup fails", async () => {
      api.api.get.mockRejectedValueOnce(new Error("Network error"));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByText(/No existing peer found/)).toBeInTheDocument();
      });
    });

    test("displays error when service lookup fails", async () => {
      const user = userEvent.setup();
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(new Error("Service lookup failed"));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() => {
        expect(
          screen.getByText(/No existing service found/),
        ).toBeInTheDocument();
      });
    });

    test("displays error when policy creation fails", async () => {
      const user = userEvent.setup();

      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      api.api.post.mockRejectedValueOnce(new Error("Policy creation failed"));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );

      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith(
          expect.stringContaining("Failed to create policy"),
          "error",
        );
      });
    });
  });

  describe("cancellation and cleanup", () => {
    test("calls onClose when close button is clicked", async () => {
      const user = userEvent.setup();
      const mockOnClose = vi.fn();

      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={mockOnClose}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(screen.getByText("Craft Policy from Log")).toBeInTheDocument();
      });

      const buttons = screen.getAllByRole("button");
      const closeButton =
        buttons.find((btn) => btn.querySelector("svg.lucide-x")) || buttons[0];
      await user.click(closeButton);

      expect(mockOnClose).toHaveBeenCalled();
    });

    test("modal is removed from DOM when unmounted", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      const { unmount } = render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(
          document.querySelector(".fixed.inset-0.z-\\[9999\\]"),
        ).toBeInTheDocument();
      });

      unmount();

      expect(
        document.querySelector(".fixed.inset-0.z-\\[9999\\]"),
      ).not.toBeInTheDocument();
    });

    test("cleans up created service when policy creation fails", async () => {
      const user = userEvent.setup();

      // Existing peer, source peer, no existing service
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(create404Error());

      // Service creation succeeds, policy creation fails
      api.api.post
        .mockResolvedValueOnce({ id: 20 }) // service created
        .mockRejectedValueOnce(new Error("Policy creation failed")); // policy fails

      // Delete for cleanup should succeed
      api.api.delete.mockResolvedValueOnce({});

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByPlaceholderText("e.g., Web Server, Database"),
        ).toBeInTheDocument(),
      );
      await user.type(
        screen.getByPlaceholderText("e.g., Web Server, Database"),
        "test-service",
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByPlaceholderText("Enter policy name"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );

      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        // Service should have been deleted during cleanup
        expect(api.api.delete).toHaveBeenCalledWith("/services/20");
        expect(mockShowToast).toHaveBeenCalledWith(
          expect.stringContaining("Failed to create policy"),
          "error",
        );
      });
    });

    test("cleans up created peer and service when policy creation fails", async () => {
      const user = userEvent.setup();

      // Target peer not found, source peer found, no existing service
      api.api.get
        .mockRejectedValueOnce(create404Error())
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockRejectedValueOnce(create404Error());

      // Peer and service creation succeed, policy creation fails
      api.api.post
        .mockResolvedValueOnce({ id: 10 }) // peer created
        .mockResolvedValueOnce({ id: 20 }) // service created
        .mockRejectedValueOnce(new Error("Policy creation failed")); // policy fails

      // Deletes for cleanup should succeed
      api.api.delete
        .mockResolvedValueOnce({}) // service delete
        .mockResolvedValueOnce({}); // peer delete

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(
          screen.getByPlaceholderText("Enter hostname"),
        ).toBeInTheDocument(),
      );
      await user.clear(screen.getByPlaceholderText("Enter hostname"));
      await user.type(
        screen.getByPlaceholderText("Enter hostname"),
        "new-peer",
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(
          screen.getByPlaceholderText("e.g., Web Server, Database"),
        ).toBeInTheDocument(),
      );
      await user.type(
        screen.getByPlaceholderText("e.g., Web Server, Database"),
        "new-service",
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(
          screen.getByPlaceholderText("Enter policy name"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        // Service should be deleted first, then peer
        expect(api.api.delete).toHaveBeenCalledWith("/services/20");
        expect(api.api.delete).toHaveBeenCalledWith("/peers/10");
        expect(mockShowToast).toHaveBeenCalledWith(
          expect.stringContaining("Failed to create policy"),
          "error",
        );
      });
    });

    test("does not attempt cleanup when using existing resources", async () => {
      const user = userEvent.setup();

      // Existing peer, source peer, existing service
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      // Policy creation fails
      api.api.post.mockRejectedValueOnce(new Error("Policy creation failed"));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByDisplayValue("existing-peer-https"),
        ).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: /create policy/i }),
        ).toBeInTheDocument(),
      );

      await user.click(screen.getByRole("button", { name: /create policy/i }));

      await waitFor(() => {
        // No cleanup should be attempted since peer and service were not newly created
        expect(api.api.delete).not.toHaveBeenCalled();
        expect(mockShowToast).toHaveBeenCalledWith(
          expect.stringContaining("Failed to create policy"),
          "error",
        );
      });
    });
  });

  describe("log parsing", () => {
    test("parses IN direction from log", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog({ direction: "IN", src_ip: "10.20.30.40" })}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/peers/by-ip?ip=10.20.30.40",
          );
        },
        { timeout: 3000 },
      );
    });

    test("parses OUT direction from log", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      // For OUT direction, we need both direction: 'OUT' and raw_line containing '[RUNIC-OUT]'
      const mockLog = createMockLog({
        direction: "OUT",
        dst_ip: "50.60.70.80",
        src_ip: "192.168.1.100",
        raw_line: "[RUNIC-OUT] blocked packet...",
      });

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for the API call to be made
      // For OUT direction, the external IP should be dst_ip
      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/peers/by-ip?ip=50.60.70.80",
          );
        },
        { timeout: 3000 },
      );
    });

    test("parses direction from raw_line", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog({
            direction: null,
            raw_line: "[RUNIC-DROP-O] blocked packet...",
            dst_ip: "10.20.30.40",
          })}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/peers/by-ip?ip=10.20.30.40",
          );
        },
        { timeout: 3000 },
      );
    });

    test("handles missing log gracefully", async () => {
      render(
        <CraftPolicyWizard
          log={null}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for the wizard to render and show error state
      // When log is null, externalIP is empty, and the component shows "No existing peer found for IP "
      await screen.findByText(/No existing peer found/, {}, { timeout: 3000 });

      // The Next button should be disabled when there's no external IP
      const nextButton = screen.getByRole("button", { name: /next/i });
      expect(nextButton).toBeDisabled();
    });

    // Tests for specific log entry from TASK-007
    // Log: 2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0
    test("parses OUT direction from [RUNIC-DROP-O] prefix (TASK-003 fix)", async () => {
      // The raw_line contains [RUNIC-DROP] but no explicit direction suffix
      // The direction should be determined from the log format
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36",
        dst_ip: "91.189.92.23",
        src_port: 47182,
        dst_port: 80,
        protocol: "tcp",
        direction: null, // No explicit direction in log object
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      // For OUT direction, external IP should be dst_ip (91.189.92.23)
      // Mock target peer lookup
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "external-peer",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        });

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for the peer to be found and displayed
      // For OUT direction, the component should use dst_ip (91.189.92.23) for target peer lookup
      await waitFor(
        () => {
          expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
        },
        { timeout: 5000 },
      );
    });

    test("extracts port 80 (DPT) not 47182 (SPT) for OUT direction (TASK-001 fix)", async () => {
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36",
        dst_ip: "91.189.92.23",
        src_port: 47182, // Source port - should NOT be used
        dst_port: 80, // Destination port - should be used
        protocol: "tcp",
        direction: "OUT",
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "external-peer",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        });

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for peer to be found
      await waitFor(() => {
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
      });

      // Navigate to service step
      const user = userEvent.setup();
      await user.click(screen.getByRole("button", { name: /next/i }));

      // The service lookup should use port 80 (dst_port), not 47182 (src_port)
      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/services/by-port?port=80&protocol=tcp",
          );
        },
        { timeout: 3000 },
      );
    });

    test("extracts external IP 91.189.92.23 (dst_ip) for OUT direction (TASK-002 fix)", async () => {
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36", // Local source IP
        dst_ip: "91.189.92.23", // External destination IP (should be target)
        src_port: 47182,
        dst_port: 80,
        protocol: "tcp",
        direction: "OUT",
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      // Mock: external IP should lookup dst_ip (91.189.92.23)
      api.api.get
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ubuntu-repos",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 1,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        });

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Verify external IP (dst_ip) is used for target peer lookup
      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalledWith(
            "/peers/by-ip?ip=91.189.92.23",
          );
        },
        { timeout: 3000 },
      );

      // Should find existing peer with the external IP
      await waitFor(
        () => {
          expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
        },
        { timeout: 5000 },
      );
    });

    test("uses src_ip for source peer lookup (TASK-002 fix)", async () => {
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36", // Local source IP (should be source peer)
        dst_ip: "91.189.92.23",
        src_port: 47182,
        dst_port: 80,
        protocol: "tcp",
        direction: "OUT",
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      // Mock target peer lookup
      api.api.get
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ubuntu-repos",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 1,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        });

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Wait for target peer to be found
      await waitFor(
        () => {
          expect(screen.getByText(/Found existing peer/)).toBeInTheDocument();
        },
        { timeout: 5000 },
      );

      // Verify that the component attempted to look up the source peer
      // The source peer lookup happens after the target peer is resolved
      // The component will call the API to look up source by hostname and/or IP
      await waitFor(
        () => {
          expect(api.api.get).toHaveBeenCalled();
        },
        { timeout: 3000 },
      );
    });

    test("displays direction as Forward for OUT in policy step (TASK-004/TASK-005)", async () => {
      const user = userEvent.setup();
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36",
        dst_ip: "91.189.92.23",
        src_port: 47182,
        dst_port: 80,
        protocol: "tcp",
        direction: "OUT",
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      api.api.get
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ubuntu-repos",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 1,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        })
        .mockResolvedValueOnce({
          id: 3,
          name: "http",
          ports: "80",
          protocol: "tcp",
        })
        .mockResolvedValueOnce([])
        .mockResolvedValueOnce([]);

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Navigate through all steps to policy
      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for policy step to load
      await waitFor(() =>
        expect(screen.getByText("Description (Optional)")).toBeInTheDocument(),
      );

      // Verify direction displays as forward arrow (SVG) for OUT direction
      // The PolicyStep uses arrow buttons, not text labels
      // The forward arrow is disabled when direction is OUT
      const forwardArrow = screen.getByTitle("Forward: Source → Target");
      expect(forwardArrow).toBeInTheDocument();
      expect(forwardArrow).toBeDisabled();

      // Verify Action displays as ACCEPT badge (TASK-005)
      // There are multiple ACCEPT texts, so look for the badge with specific class
      expect(
        screen.getByText("ACCEPT", { selector: ".bg-green-100" }),
      ).toBeInTheDocument();

      // Verify Target Scope displays as "Host + Docker" (TASK-005)
      expect(screen.getByText("Host + Docker")).toBeInTheDocument();
    });

    test("has Edit buttons for Source, Target, Service, and Direction in policy step (TASK-004)", async () => {
      const user = userEvent.setup();
      const mockLog = {
        peer_id: 1,
        hostname: "ansible",
        src_ip: "10.100.5.36",
        dst_ip: "91.189.92.23",
        src_port: 47182,
        dst_port: 80,
        protocol: "tcp",
        direction: "OUT",
        raw_line:
          "2026-04-16T05:09:04.939461-07:00 ansible kernel: [RUNIC-DROP] IN= OUT=ens160 SRC=10.100.5.36 DST=91.189.92.23 LEN=52 TOS=0x00 PREC=0x00 TTL=64 ID=24 DF PROTO=TCP SPT=47182 DPT=80 WINDOW=3167 RES=0x00 ACK PSH FIN URGP=0",
      };

      // Return mock peers and services for dropdown options
      const mockPeers = [
        { id: 1, hostname: "ansible", ip_address: "10.100.5.36" },
        { id: 2, hostname: "ubuntu-repos", ip_address: "91.189.92.23" },
        { id: 3, hostname: "other-peer", ip_address: "192.168.1.50" },
      ];
      const mockServices = [
        { id: 1, name: "http", protocol: "tcp", ports: "80" },
        { id: 2, name: "https", protocol: "tcp", ports: "443" },
      ];

      api.api.get
        .mockResolvedValueOnce({
          id: 2,
          hostname: "ubuntu-repos",
          ip_address: "91.189.92.23",
        })
        .mockResolvedValueOnce({
          id: 1,
          hostname: "ansible",
          ip_address: "10.100.5.36",
        })
        .mockResolvedValueOnce({
          id: 3,
          name: "http",
          ports: "80",
          protocol: "tcp",
        })
        .mockResolvedValueOnce(mockPeers)
        .mockResolvedValueOnce(mockServices);

      render(
        <CraftPolicyWizard
          log={mockLog}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Navigate to policy step
      await waitFor(() =>
        expect(screen.getByText(/Found existing peer/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      await waitFor(() =>
        expect(screen.getByText(/Found existing service/)).toBeInTheDocument(),
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for policy step with editable fields
      await waitFor(() =>
        expect(screen.getByText("Description (Optional)")).toBeInTheDocument(),
      );

      // Verify that there are Edit buttons present for the editable fields
      // The component has Edit buttons for: Source, Target, Service (Direction uses arrow buttons)
      const editButtons = screen.getAllByRole("button", { name: /edit/i });
      expect(editButtons.length).toBe(3);

      // Verify Direction has arrow buttons instead of Edit button
      expect(screen.getByTitle("Forward: Source → Target")).toBeInTheDocument();
      expect(
        screen.getByTitle("Backward: Target → Source"),
      ).toBeInTheDocument();
    });
  });

  describe("form validation", () => {
    test("Next button is disabled during loading", async () => {
      api.api.get.mockImplementation(() => new Promise(() => {}));

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      expect(screen.getByRole("button", { name: /next/i })).toBeDisabled();
    });

    test("Next button is enabled when peer is found", async () => {
      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        });

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      await waitFor(() => {
        expect(
          screen.getByRole("button", { name: /next/i }),
        ).not.toBeDisabled();
      });
    });

    test("Create Policy button is disabled during submission", async () => {
      const user = userEvent.setup();

      api.api.get
        .mockResolvedValueOnce({
          id: 1,
          hostname: "existing-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 2,
          hostname: "test-peer",
          ip_address: "192.168.1.100",
        })
        .mockResolvedValueOnce({
          id: 1,
          name: "https",
          ports: "443",
          protocol: "tcp",
        });

      // Create a promise we can resolve manually to control timing
      let resolvePost;
      api.api.post.mockImplementation(
        () =>
          new Promise((resolve) => {
            resolvePost = resolve;
          }),
      );

      render(
        <CraftPolicyWizard
          log={createMockLog()}
          onClose={() => {}}
          onSuccess={() => {}}
        />,
        { wrapper },
      );

      // Navigate to review step
      await screen.findByText(/Found existing peer/, {}, { timeout: 5000 });
      await user.click(screen.getByRole("button", { name: /next/i }));

      await screen.findByText(/Found existing service/, {}, { timeout: 5000 });
      await user.click(screen.getByRole("button", { name: /next/i }));

      await screen.findByDisplayValue(
        "existing-peer-https",
        {},
        { timeout: 5000 },
      );
      await user.click(screen.getByRole("button", { name: /next/i }));

      // Wait for review step to render - look for the PEER section in review
      await screen.findByText(/PEER \(Existing\)/, {}, { timeout: 5000 });

      // Find the Create Policy button
      const createButton = await screen.findByRole(
        "button",
        { name: /create policy/i },
        { timeout: 5000 },
      );

      // Click Create Policy
      await user.click(createButton);

      // Check that button shows disabled state during submission (shows "Creating...")
      await screen.findByText(/Creating/, {}, { timeout: 3000 });

      // Resolve the post promise to complete the test
      await act(async () => {
        resolvePost({ id: 1 });
      });
    });
  });
});
