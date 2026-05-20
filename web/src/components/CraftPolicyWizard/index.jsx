import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import ReactDOM from "react-dom";
import {
  X,
  ChevronLeft,
  ChevronRight,
  Check,
  Loader2,
  Server,
  Package,
  Shield,
} from "lucide-react";
import { api, QUERY_KEYS } from "../../api/client";
import { useToastContext } from "../../hooks/ToastContext";
import { useFocusTrap } from "../../hooks/useFocusTrap";
import { useQueryClient } from "@tanstack/react-query";
import { parseCompositePeerValue } from "../../utils/peerUtils";
import { getPeerDisplayValue } from "./shared";
import { logger } from "../../utils/logger";
import StepIndicator from "../StepIndicator";
import PeerStep from "./PeerStep";
import ServiceStep from "./ServiceStep";
import PolicyStep from "./PolicyStep";
import ReviewStep from "./ReviewStep";

// Re-export for backward compatibility (used by tests)
export { getPeerDisplayValue } from "./shared";

const BASE_PROTOCOL_OPTIONS = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "both", label: "TCP+UDP" },
];

function useProtocolOptions(currentProtocol) {
  return useMemo(() => {
    if (currentProtocol === "icmp" || currentProtocol === "igmp") {
      return [
        { value: currentProtocol, label: currentProtocol.toUpperCase(), disabled: true },
        ...BASE_PROTOCOL_OPTIONS,
      ];
    }
    return BASE_PROTOCOL_OPTIONS;
  }, [currentProtocol]);
}

export default function CraftPolicyWizard({ log, onClose, onSuccess }) {
  const qc = useQueryClient();
  const { showToast } = useToastContext();
  const modalRef = useRef(null);

  useFocusTrap(modalRef, true);

  // Parse log to extract direction, external IP, port, protocol
  const parseLog = useCallback((logEvent) => {
    if (!logEvent)
      return { direction: null, externalIP: "", port: 0, protocol: "tcp" };

    // Check for direction prefix in raw_line (e.g., "[RUNIC-DROP-I] " or "[RUNIC-DROP-O] ")
    const rawLine = logEvent.raw_line || "";
    let direction = logEvent.direction || null;

    if (rawLine.includes("[RUNIC-DROP-I]")) {
      direction = "IN";
    } else if (rawLine.includes("[RUNIC-DROP-O]")) {
      direction = "OUT";
    }

    // Determine external IP and port based on direction
    let externalIP = "";
    let port = 0;
    const protocol = logEvent.protocol?.toLowerCase() || "tcp";

    if (direction === "IN") {
      // Incoming traffic: source is external, destination is local
      externalIP = logEvent.src_ip || "";
      port = logEvent.dst_port || 0;
    } else if (direction === "OUT") {
      // Outgoing traffic: destination is external, source is local
      externalIP = logEvent.dst_ip || "";
      port = logEvent.dst_port || 0;
    } else {
      // Fallback: use src_ip as external
      externalIP = logEvent.src_ip || "";
      port = logEvent.dst_port || 0;
    }

    return { direction, externalIP, port, protocol };
  }, []);

  const parsedLog = parseLog(log);

  // State machine: 'peer' | 'service' | 'policy' | 'review'
  const [step, setStep] = useState("peer");
  const direction = parsedLog.direction;
  const externalIP = parsedLog.externalIP;
  const port = parsedLog.port;
  const protocol = parsedLog.protocol;

  // User selections
  const [existingTargetPeer, setExistingTargetPeer] = useState(null); // External peer (target)
  const [newTargetPeer, setNewTargetPeer] = useState({
    hostname: "",
    ip_address: parsedLog.externalIP,
  os_type: "linux",
  arch: "",
  });
  const [existingSourcePeer, setExistingSourcePeer] = useState(null); // Local peer (source from log)
  const [existingService, setExistingService] = useState(null);
  const [newService, setNewService] = useState({
    name: "",
    protocol: parsedLog.protocol,
    ports: protocol === "icmp" || protocol === "igmp" ? "" : String(parsedLog.port),
    description: "",
    source_ports: "",
  });
  const [policyConfig, setPolicyConfig] = useState({
    name: "",
    priority: 100,
    enabled: true,
    description: "",
    target_scope: "host", // Changed from 'both'
  });

  // UI state
  const [createTargetPeerMode, setCreateTargetPeerMode] = useState(false);
  const [targetPeerLoading, setTargetPeerLoading] = useState(true);
  const [targetPeerError, setTargetPeerError] = useState(null);
  const [_sourcePeerLoading, setSourcePeerLoading] = useState(true);
  const [_sourcePeerError, setSourcePeerError] = useState(null);
  const [serviceLoading, setServiceLoading] = useState(true);
  const [serviceError, setServiceError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [formErrors, setFormErrors] = useState({});

  // Editable selections for Source/Target/Service/Direction overrides
  const [selectedSourcePeerId, setSelectedSourcePeerId] = useState(null);
  const [selectedTargetPeerId, setSelectedTargetPeerId] = useState(null);
  const [selectedServiceId, setSelectedServiceId] = useState(null);
  const [selectedDirection, setSelectedDirection] = useState(null);
  const [editMode, setEditMode] = useState({
    source: false,
    target: false,
    service: false,
    direction: false,
  });

  // All available peers, groups, and services for dropdown options
  const [allPeers, setAllPeers] = useState([]);
  const [allGroups, setAllGroups] = useState([]);
  const [allServices, setAllServices] = useState([]);
  const [peersLoading, setPeersLoading] = useState(true);

  // Fetch target peer by external IP on mount (Peer Step)
  useEffect(() => {
    if (!externalIP) {
      setTargetPeerLoading(false);
      setTargetPeerError({ message: "No external IP found in log" });
      return;
    }

    let isMounted = true;

    const fetchTargetPeerByIP = async () => {
      setTargetPeerLoading(true);
      setTargetPeerError(null);
      try {
        const peer = await api.get(
          `/peers/by-ip?ip=${encodeURIComponent(externalIP)}`,
        );
        if (isMounted) {
          setExistingTargetPeer(peer);
          setCreateTargetPeerMode(false);
        }
      } catch (err) {
        if (isMounted) {
          if (err.status === 404) {
            setTargetPeerError({ message: "No peer found", status: 404 });
            setCreateTargetPeerMode(true);
            // Pre-fill hostname with a suggestion
            setNewTargetPeer((prev) => ({
              ...prev,
              hostname: `peer-${externalIP.replace(/\./g, "-")}`,
              ip_address: externalIP,
            }));
          } else {
            setTargetPeerError({ message: err.message });
          }
          setExistingTargetPeer(null);
        }
      } finally {
        if (isMounted) {
          setTargetPeerLoading(false);
        }
      }
    };

    fetchTargetPeerByIP();
    return () => {
      isMounted = false;
    };
  }, [externalIP]);

  // Fetch source peer by hostname or src_ip from log (local machine)
  useEffect(() => {
    const sourceIP = log?.src_ip;
    const sourceHostname = log?.hostname;

    if (!sourceIP && !sourceHostname) {
      setSourcePeerLoading(false);
      setSourcePeerError({ message: "No source info found in log" });
      return;
    }

    let isMounted = true;

    const fetchSourcePeer = async () => {
      setSourcePeerLoading(true);
      setSourcePeerError(null);
      try {
        // Try to find peer by hostname first, then by src_ip
        let peer = null;
        if (sourceHostname) {
          try {
            // Use dedicated /by-hostname endpoint for exact match lookup
            peer = await api.get(
              `/peers/by-hostname?hostname=${encodeURIComponent(sourceHostname)}`,
            );
          } catch {
            // Try by IP if hostname lookup fails
          }
        }
        if (!peer && sourceIP) {
          try {
            peer = await api.get(
              `/peers/by-ip?ip=${encodeURIComponent(sourceIP)}`,
            );
          } catch {
            // Peer not found
          }
        }
        if (isMounted) {
          if (peer) {
            setExistingSourcePeer(peer);
          } else {
            // Create a placeholder for the local source peer (it might not exist in DB yet)
            setExistingSourcePeer({
              id: null,
              hostname: sourceHostname || `local-${sourceIP}`,
              ip_address: sourceIP,
            });
          }
        }
      } catch (err) {
        if (isMounted) {
          setSourcePeerError({ message: err.message });
          // Still set a placeholder for the source peer
          setExistingSourcePeer({
            id: null,
            hostname: sourceHostname || `local-${sourceIP}`,
            ip_address: sourceIP,
          });
        }
      } finally {
        if (isMounted) {
          setSourcePeerLoading(false);
        }
      }
    };

    fetchSourcePeer();
    return () => {
      isMounted = false;
    };
  }, [log?.hostname, log?.src_ip]);

  // Fetch service by port/protocol when entering service step
  useEffect(() => {
    if (step !== "service") return;
  if (!port && !protocol) {
    setServiceLoading(false);
    setServiceError({ message: "No port or protocol found in log" });
    return;
  }

    let isMounted = true;

    const fetchServiceByPort = async () => {
      setServiceLoading(true);
      setServiceError(null);
      try {
        const service = await api.get(
          `/services/by-port?port=${port}&protocol=${protocol}`,
        );
        if (isMounted) {
          setExistingService(service);
        }
      } catch (err) {
        if (isMounted) {
          if (err.status === 404) {
            setServiceError({ message: "No service found", status: 404 });
            setExistingService(null);
          } else {
            setServiceError({ message: err.message });
            setExistingService(null);
          }
        }
      } finally {
        if (isMounted) {
          setServiceLoading(false);
        }
      }
    };

    fetchServiceByPort();
    return () => {
      isMounted = false;
    };
  }, [step, port, protocol]);

  // Generate policy name when moving to policy step
  useEffect(() => {
    if (step === "policy" && !policyConfig.name) {
      const targetPeerName =
        existingTargetPeer?.hostname || newTargetPeer.hostname || "peer";
      const serviceName = existingService?.name || newService.name || "service";
      const generatedName = `${targetPeerName}-${serviceName}`
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, "-")
        .substring(0, 50);
      setPolicyConfig((prev) => ({ ...prev, name: generatedName }));
    }
  }, [
    step,
    existingTargetPeer,
    newTargetPeer,
    existingService,
    newService,
    policyConfig.name,
  ]);

  // Fetch all peers and services for dropdown options when entering policy step
  useEffect(() => {
    if (step !== "policy") return;

    let isMounted = true;
    setPeersLoading(true);

    const fetchAllData = async () => {
      try {
        const [peersData, groupsData, servicesData] = await Promise.all([
          api.get("/peers"),
          api.get("/groups"),
          api.get("/services"),
        ]);
        if (isMounted) {
          setAllPeers(peersData || []);
          setAllGroups(groupsData || []);
          setAllServices(servicesData || []);
        }
      } catch (err) {
        if (isMounted) {
          logger.error("Failed to fetch peers/services:", err);
        }
      } finally {
        if (isMounted) {
          setPeersLoading(false);
        }
      }
    };

    fetchAllData();
    return () => {
      isMounted = false;
    };
  }, [step]);

  // Convert peers to options format for SearchableSelect
  const peerOptions = [
    // Groups first
    ...(allGroups || []).map((g) => ({
      value: `group:${g.id}`,
      label: g.name,
      sublabel: `${g.peer_count || 0} peers`,
    })),
    // Then peers
    ...allPeers.flatMap((peer) => {
      const hasMultipleIPs = peer.ips && peer.ips.length > 1;
      if (hasMultipleIPs) {
        // Multi-IP peer: create one entry per IP with composite value
        return peer.ips.map((peerIp) => ({
          value: `peer:${peer.id}:${peerIp.ip_address}`,
          label: `${peer.hostname || peer.ip_address || "Unknown"} - ${peerIp.ip_address}`,
          sublabel: peerIp.ip_address,
        }));
      }
      // Single-IP peer: use peer id directly (backward compatible)
      return [{
        value: peer.id,
        label: peer.hostname || peer.ip_address || "Unknown",
        sublabel: peer.ip_address,
      }];
    }),
    // Add pending target peer if creating new
    ...(createTargetPeerMode
      ? [
          {
            value: "pending-target",
            label: newTargetPeer.hostname || newTargetPeer.ip_address,
            sublabel: newTargetPeer.ip_address,
            isPending: true,
          },
        ]
      : []),
    // Add existing target peer if it doesn't have an ID yet (placeholder)
    ...(existingTargetPeer && !existingTargetPeer.id
      ? [
          {
            value: "pending-target",
            label: existingTargetPeer.hostname || existingTargetPeer.ip_address,
            sublabel: existingTargetPeer.ip_address,
            isPending: true,
          },
        ]
      : []),
    // Add placeholder for source peer if not existing
    ...(existingSourcePeer && !existingSourcePeer.id
      ? [
          {
            value: "pending-source",
            label: existingSourcePeer.hostname || existingSourcePeer.ip_address,
            sublabel: existingSourcePeer.ip_address,
            isPending: true,
          },
        ]
      : []),
  ];

  // Convert services to options format for SearchableSelect
  const serviceOptions = allServices.map((service) => ({
    value: service.id,
    label: service.name,
    sublabel: `${service.protocol}:${service.ports}`,
  }));

  // Compute protocol options dynamically to include ICMP/IGMP when auto-populated
  const protocolOptions = useProtocolOptions(newService.protocol);

  // Compute effective target peer once to avoid duplicated ternary
  const effectiveTargetPeer = createTargetPeerMode ? newTargetPeer : (existingTargetPeer || newTargetPeer);

  // Compute direction-aware source/target peers for policy purposes.
  // The raw state variables represent how the peers were looked up:
  //   existingTargetPeer = external peer (looked up by externalIP)
  //   existingSourcePeer = local peer (looked up by log hostname/src_ip)
  //
  // For OUT logs: Source=local(initiator), Target=external(receiver) — matches raw state
  // For IN logs:  Source=external(initiator), Target=local(receiver) — swap needed
  //
  // This matches the Policy page and importer conventions where:
  //   IN:  Source=external, Target=local, direction=backward → target(local) gets rules
  //   OUT: Source=local, Target=external, direction=forward → source(local) gets rules
  const policySourcePeer = direction === "IN" ? effectiveTargetPeer : existingSourcePeer;
  const policyTargetPeer = direction === "IN" ? existingSourcePeer : effectiveTargetPeer;

  // Get display values for editable fields
  const getSourceDisplay = () =>
    getPeerDisplayValue({
      selectedPeerId: selectedSourcePeerId,
      allPeers,
      fallbackPeer: policySourcePeer,
      fallback: "Unknown",
    });

  const getTargetDisplay = () =>
    getPeerDisplayValue({
      selectedPeerId: selectedTargetPeerId,
      allPeers,
      fallbackPeer: policyTargetPeer,
      fallback: "Unknown",
    });

  // Helper to toggle edit mode for a field
  const toggleEditMode = (field) => {
    setEditMode((prev) => ({ ...prev, [field]: !prev[field] }));
  };

  // Validation functions
  const validatePeerStep = useCallback(() => {
    const errors = {};
    if (createTargetPeerMode || !existingTargetPeer) {
      if (!newTargetPeer.hostname?.trim()) {
        errors.hostname = "Hostname is required";
      }
      if (!newTargetPeer.ip_address?.trim()) {
        errors.ip_address = "IP Address is required";
      }
    }
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  }, [createTargetPeerMode, existingTargetPeer, newTargetPeer]);

  const validateServiceStep = useCallback(() => {
    const errors = {};
    if (!existingService) {
      if (!newService.name?.trim()) {
        errors.name = "Service name is required";
      }
      if (!newService.ports?.trim() && newService.protocol !== "icmp" && newService.protocol !== "igmp") {
        errors.ports = "Ports are required";
      }
    }
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  }, [existingService, newService]);

  const validatePolicyStep = useCallback(() => {
    const errors = {};
    if (!policyConfig.name?.trim()) {
      errors.name = "Policy name is required";
    }
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  }, [policyConfig]);

  // Navigation handlers
  const handleBack = () => {
    setFormErrors({});
    switch (step) {
      case "service":
        setStep("peer");
        break;
      case "policy":
        setStep("service");
        break;
      case "review":
        setStep("policy");
        break;
    }
  };

  const handleNext = () => {
    switch (step) {
      case "peer":
        if (validatePeerStep()) {
          setStep("service");
        }
        break;
      case "service":
        if (validateServiceStep()) {
          setStep("policy");
        }
        break;
      case "policy":
        if (validatePolicyStep()) {
          setStep("review");
        }
        break;
    }
  };

  // Submit handler
  const handleSubmit = async () => {
    setSubmitting(true);
    setFormErrors({});

    // Track newly created resources for cleanup on failure
    let createdSourcePeerId = null;
    let createdTargetPeerId = null;
    let createdServiceId = null;

  try {
    // Source and Target assignment follows the Policy page convention:
      // IN logs:  Source=external(initiator), Target=local(receiver)
      // OUT logs: Source=local(initiator), Target=external(receiver)
      // Use user-selected overrides if provided, otherwise use auto-detected values
      // Handle pending peer selections and composite values (e.g., "peer:5:10.20.10.20")
      const sourceComposite = parseCompositePeerValue(selectedSourcePeerId);
      const targetComposite = parseCompositePeerValue(selectedTargetPeerId);

      // Determine source/target peer IDs based on direction.
      // For IN logs: source = external peer (was existingTargetPeer), target = local peer (was existingSourcePeer)
      // For OUT logs: source = local peer (existingSourcePeer), target = external peer (existingTargetPeer)
      const resolvedSourcePeerId = direction === "IN" ? existingTargetPeer?.id : existingSourcePeer?.id;
      const resolvedTargetPeerId = direction === "IN" ? existingSourcePeer?.id : existingTargetPeer?.id;

      let sourcePeerId = sourceComposite
        ? sourceComposite.id
        : selectedSourcePeerId === "pending-source"
        ? null
        : selectedSourcePeerId || resolvedSourcePeerId;
      let sourceIP = sourceComposite ? sourceComposite.ip : null;

      let targetPeerId = targetComposite
        ? targetComposite.id
        : selectedTargetPeerId === "pending-target"
        ? null
        : selectedTargetPeerId || resolvedTargetPeerId;
      let targetIP = targetComposite ? targetComposite.ip : null;

    let serviceId = selectedServiceId || existingService?.id;
    const policyDirection = selectedDirection || direction;

      // Step 0: Create source peer if needed
      // For IN logs: source = external peer; For OUT logs: source = local peer
      // Only create if no existing peer and user hasn't selected an override
      if (!selectedSourcePeerId) {
        const needsSourceCreation = direction === "IN"
          ? (!existingTargetPeer || createTargetPeerMode) // IN: source is external
          : !existingSourcePeer?.id; // OUT: source is local

        if (needsSourceCreation) {
          // Determine the peer data to use for source creation based on direction
          const sourcePeerData = direction === "IN"
            ? { hostname: newTargetPeer.hostname, ip_address: newTargetPeer.ip_address, os_type: newTargetPeer.os_type || null, arch: newTargetPeer.arch || null }
            : { hostname: existingSourcePeer.hostname, ip_address: existingSourcePeer.ip_address, os_type: existingSourcePeer.os_type || null, arch: existingSourcePeer.arch || null };
          const createdSourcePeer = await api.post("/peers", {
            ...sourcePeerData,
            is_manual: true,
          });
          sourcePeerId = createdSourcePeer.id;
          createdSourcePeerId = createdSourcePeer.id; // Track for potential cleanup
          showToast("Source peer created successfully", "success");
        }
      }

      // Step 1: Create target peer if needed
      // For IN logs: target = local peer; For OUT logs: target = external peer
      // Only create if no existing peer and user hasn't selected an override
      if (!selectedTargetPeerId) {
        const needsTargetCreation = direction === "IN"
          ? !existingSourcePeer?.id // IN: target is local
          : (!existingTargetPeer || createTargetPeerMode); // OUT: target is external

        if (needsTargetCreation) {
          // Determine the peer data to use for target creation based on direction
          const targetPeerData = direction === "IN"
            ? { hostname: existingSourcePeer.hostname, ip_address: existingSourcePeer.ip_address, os_type: existingSourcePeer.os_type || null, arch: existingSourcePeer.arch || null }
            : { hostname: newTargetPeer.hostname, ip_address: newTargetPeer.ip_address, os_type: newTargetPeer.os_type || null, arch: newTargetPeer.arch || null };
          const createdTargetPeer = await api.post("/peers", {
            ...targetPeerData,
            is_manual: true,
          });
          targetPeerId = createdTargetPeer.id;
          createdTargetPeerId = createdTargetPeer.id; // Track for potential cleanup
          showToast("Target peer created successfully", "success");
        }
      }

      // Step 2: Create service if needed
      // Only create if no existing service and user hasn't selected an override
      if (!selectedServiceId && !existingService) {
        const createdService = await api.post("/services", {
          name: newService.name,
          protocol: newService.protocol,
          ports: newService.ports,
          source_ports: newService.source_ports || null,
          description: newService.description || null,
        });
        serviceId = createdService.id;
        createdServiceId = createdService.id; // Track for potential cleanup
        showToast("Service created successfully", "success");
      }

      // Step 3: Create policy
      // IN: Source=external, Target=local; OUT: Source=local, Target=external
    await api.post("/policies", {
      name: policyConfig.name,
      description: policyConfig.description || null,
      source_id: sourcePeerId,
      source_type: "peer",
      source_ip: sourceIP || undefined,
      service_id: serviceId,
      target_id: targetPeerId,
      target_type: "peer",
      target_ip: targetIP || undefined,
      action: "ACCEPT",
      priority: policyConfig.priority,
      enabled: policyConfig.enabled,
      direction:
        policyDirection === "both"
          ? "both"
          : policyDirection === "forward" || policyDirection === "OUT"
            ? "forward"
            : "backward",
      target_scope: policyConfig.target_scope || "host",
    });

      showToast("Policy created successfully", "success");

      // Invalidate relevant queries
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.services() });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() });
      qc.invalidateQueries({ queryKey: ["pending-changes"] });
      qc.invalidateQueries({ queryKey: QUERY_KEYS.logs() });

      onSuccess?.();
      onClose?.();
    } catch (err) {
      // Cleanup orphaned resources on failure
      const cleanupErrors = [];
      if (createdServiceId) {
        try {
          await api.delete(`/services/${createdServiceId}`);
        } catch (cleanupErr) {
          cleanupErrors.push(`service: ${cleanupErr.message}`);
        }
      }
      if (createdTargetPeerId) {
        try {
          await api.delete(`/peers/${createdTargetPeerId}`);
        } catch (cleanupErr) {
          cleanupErrors.push(`target peer: ${cleanupErr.message}`);
        }
      }
      if (createdSourcePeerId) {
        try {
          await api.delete(`/peers/${createdSourcePeerId}`);
        } catch (cleanupErr) {
          cleanupErrors.push(`source peer: ${cleanupErr.message}`);
        }
      }

      const cleanupMsg =
        cleanupErrors.length > 0
          ? ` Additionally, cleanup failed for: ${cleanupErrors.join(", ")}`
          : "";
      setFormErrors({ _general: err.message });
      showToast(
        `Failed to create policy: ${err.message}${cleanupMsg}`,
        "error",
      );
    } finally {
      setSubmitting(false);
    }
  };

  // Check if can proceed
  const canProceed = useCallback(() => {
    switch (step) {
      case "peer":
        return (
          !targetPeerLoading && (existingTargetPeer || newTargetPeer.hostname)
        );
    case "service":
      return (
        !serviceLoading &&
        (existingService || (newService.name && (newService.ports || newService.protocol === "icmp" || newService.protocol === "igmp")))
      );
      case "policy":
        return !!policyConfig.name;
      case "review":
        return true;
      default:
        return false;
    }
  }, [
    step,
    targetPeerLoading,
    existingTargetPeer,
    newTargetPeer,
    serviceLoading,
    existingService,
    newService,
    policyConfig,
  ]);

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50">
      <div
        ref={modalRef}
        className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-2xl mx-4 max-h-[90vh] flex flex-col"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
            Craft Policy from Log
          </h3>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Step Indicators */}
        <div className="px-6 pt-4 shrink-0">
          <StepIndicator
            steps={[
              { key: "peer", label: "Peer", icon: Server },
              { key: "service", label: "Service", icon: Package },
              { key: "policy", label: "Policy", icon: Shield },
              { key: "review", label: "Review", icon: Check },
            ]}
            currentStep={step}
          />
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {step === "peer" && (
            <PeerStep
              externalIP={externalIP}
              existingPeer={existingTargetPeer}
              newPeer={newTargetPeer}
              setNewPeer={setNewTargetPeer}
              peerLoading={targetPeerLoading}
              peerError={targetPeerError}
              createNewPeerMode={createTargetPeerMode}
              setCreateNewPeerMode={setCreateTargetPeerMode}
              formErrors={formErrors}
            />
          )}

        {step === "service" && (
          <ServiceStep
            port={port}
            protocol={protocol}
            existingService={existingService}
            newService={newService}
            setNewService={setNewService}
            serviceLoading={serviceLoading}
            serviceError={serviceError}
            formErrors={formErrors}
            protocolOptions={protocolOptions}
          />
        )}

{step === "policy" && (
          <PolicyStep
            policyConfig={policyConfig}
            setPolicyConfig={setPolicyConfig}
            service={existingService || newService}
            direction={direction}
      formErrors={formErrors}
      // Editable field props
              peerOptions={peerOptions}
              serviceOptions={serviceOptions}
              selectedSourcePeerId={selectedSourcePeerId}
              selectedTargetPeerId={selectedTargetPeerId}
              selectedServiceId={selectedServiceId}
              selectedDirection={selectedDirection}
              setSelectedSourcePeerId={setSelectedSourcePeerId}
              setSelectedTargetPeerId={setSelectedTargetPeerId}
              setSelectedServiceId={setSelectedServiceId}
              setSelectedDirection={setSelectedDirection}
              editMode={editMode}
              toggleEditMode={toggleEditMode}
              peersLoading={peersLoading}
              getSourceDisplay={getSourceDisplay}
              getTargetDisplay={getTargetDisplay}
              allPeers={allPeers}
              allGroups={allGroups}
            />
          )}

          {step === "review" && (
            <ReviewStep
              existingPeer={existingTargetPeer}
              newPeer={newTargetPeer}
              createNewPeerMode={createTargetPeerMode}
              existingService={existingService}
              newService={newService}
              policyConfig={policyConfig}
        sourcePeer={policySourcePeer}
        targetPeer={policyTargetPeer}
      direction={direction}
      // Pass override values
              selectedSourcePeerId={selectedSourcePeerId}
              selectedTargetPeerId={selectedTargetPeerId}
              selectedServiceId={selectedServiceId}
              selectedDirection={selectedDirection}
              allPeers={allPeers}
              allServices={allServices}
            />
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-between shrink-0">
          <button
            type="button"
            onClick={handleBack}
            disabled={step === "peer"}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-none ${
              step === "peer"
                ? "text-gray-300 dark:text-gray-600 cursor-not-allowed"
                : "text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
            }`}
          >
            <ChevronLeft className="w-4 h-4" />
            Back
          </button>

          <div className="flex items-center gap-3">
            {step !== "review" ? (
              <button
                type="button"
                onClick={handleNext}
                disabled={!canProceed()}
                className="flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handleSubmit}
                disabled={submitting}
                className="flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase text-white bg-green-600 hover:bg-green-700 rounded-none disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Creating...
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    Create Policy
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  return ReactDOM.createPortal(modalContent, document.body);
}
