import { Server, Package, Shield, Check } from "lucide-react";

// Step indicators component
export default function StepIndicators({ currentStep }) {
  const steps = [
    { key: "peer", label: "Peer", icon: Server },
    { key: "service", label: "Service", icon: Package },
    { key: "policy", label: "Policy", icon: Shield },
    { key: "review", label: "Review", icon: Check },
  ];

  const currentIndex = steps.findIndex((s) => s.key === currentStep);

  return (
    <div className="flex items-center justify-center gap-2 mb-6">
      {steps.map((step, idx) => {
        const Icon = step.icon;
        const isActive = step.key === currentStep;
        const isCompleted = idx < currentIndex;

        return (
          <div key={step.key} className="flex items-center">
            <div
              className={`
                flex items-center justify-center w-8 h-8 rounded-none text-sm font-medium
                ${
                  isActive
                    ? "bg-purple-active text-white"
                    : isCompleted
                      ? "bg-green-500 text-white"
                      : "bg-gray-200 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted"
                }
              `}
            >
              {isCompleted ? (
                <Check className="w-4 h-4" />
              ) : (
                <Icon className="w-4 h-4" />
              )}
            </div>
            <span
              className={`
                ml-1.5 text-xs font-medium
                ${isActive ? "text-purple-active" : "text-gray-500 dark:text-amber-muted"}
              `}
            >
              {step.label}
            </span>
            {idx < steps.length - 1 && (
              <div
                className={`
                  w-8 h-0.5 mx-2
                  ${idx < currentIndex ? "bg-green-500" : "bg-gray-200 dark:bg-charcoal-darkest"}
                `}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
