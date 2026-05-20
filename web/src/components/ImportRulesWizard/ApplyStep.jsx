export default function ApplyStep({
  approvedRulesCount,
  approvedGroupsCount,
  approvedPeersCount,
  approvedServicesCount,
}) {
  return (
    <div className="py-8 space-y-6">
      <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral text-center">
        Confirm Import
      </h3>
      <div className="max-w-md mx-auto space-y-3">
        <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-none">
          <span className="text-gray-600 dark:text-gray-300">
            Policies to create
          </span>
          <span className="font-semibold text-gray-900 dark:text-light-neutral">
            {approvedRulesCount}
          </span>
        </div>
        <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-none">
          <span className="text-gray-600 dark:text-gray-300">
            New groups
          </span>
          <span className="font-semibold text-gray-900 dark:text-light-neutral">
            {approvedGroupsCount}
          </span>
        </div>
        <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-none">
          <span className="text-gray-600 dark:text-gray-300">
            New manual peers
          </span>
          <span className="font-semibold text-gray-900 dark:text-light-neutral">
            {approvedPeersCount}
          </span>
        </div>
        <div className="flex justify-between p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-none">
          <span className="text-gray-600 dark:text-gray-300">
            New services
          </span>
          <span className="font-semibold text-gray-900 dark:text-light-neutral">
            {approvedServicesCount}
          </span>
        </div>
      </div>
      {approvedRulesCount === 0 && (
        <p className="text-center text-orange-600 dark:text-orange-400 text-sm">
          No rules are approved. Go back and approve at least one rule.
        </p>
      )}
    </div>
  );
}
