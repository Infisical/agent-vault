import { useVaultParams } from "./shared";
import LogsView from "../../components/LogsView";

export default function LogsTab() {
  const { vaultName } = useVaultParams();
  return <LogsView endpoint={`/v1/vaults/${encodeURIComponent(vaultName)}/logs`} />;
}
