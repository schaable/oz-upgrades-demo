import { overrideTask } from "hardhat/config";
import type { HardhatPlugin } from "hardhat/types/plugins";

import "./type-extensions.js";

const plugin: HardhatPlugin = {
  id: "oz-upgrades-verification-plugin",
  hookHandlers: {
    /*     config: () => import("./hooks/config.js"),
    network: () => import("./hooks/network.js"), */
  },
  tasks: [
    overrideTask(["verify", "etherscan"])
      .setAction(async () => import("./tasks/verify/etherscan/task-action.js"))
      .build(),
  ],
  dependencies: () => [
    import("@nomicfoundation/hardhat-verify"),
    // TODO (oz): add back when upgrades-core is migrated to hh3
    // import("@openzeppelin/upgrades-core"),
  ],
};

export default plugin;
