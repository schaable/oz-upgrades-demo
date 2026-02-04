import { overrideTask } from "hardhat/config";
import type { HardhatPlugin } from "hardhat/types/plugins";

const plugin: HardhatPlugin = {
  id: "oz-upgrades-verification-plugin",
  tasks: [
    overrideTask(["verify", "etherscan"])
      .setAction(async () => import("./tasks/verify/etherscan/task-action.js"))
      .build(),
  ],
  dependencies: () => [
    import("@nomicfoundation/hardhat-verify"),
    // TODO: add back when upgrades-core is migrated to hh3
    // import("@openzeppelin/upgrades-core"),
  ],
};

export default plugin;
