import { expect, test } from "bun:test";
import {
  githubReleaseIsPrerelease,
  jsonString,
  lifecycleCycles,
  uniqueXcodeVersions,
} from "./compatibility-tracker";

test("xcode scraper skips prerelease entries", () => {
  const versions = uniqueXcodeVersions(
    [
      "<a>Xcode 27 beta 1</a>",
      "<a>Xcode 26.6 RC</a>",
      "<a>Xcode 26.5</a>",
    ].join("\n"),
  );

  expect(versions).toEqual(["26.5"]);
});

test("github release filter skips prerelease entries", () => {
  expect(
    githubReleaseIsPrerelease({
      tag_name: "llvmorg-22.0.0-rc1",
      name: "LLVM 22 release candidate",
      prerelease: false,
    }),
  ).toBe(true);

  expect(
    githubReleaseIsPrerelease({
      tag_name: "llvmorg-22.0.0",
      name: "LLVM 22.0.0",
      prerelease: true,
    }),
  ).toBe(true);
});

test("lifecycle filter skips prerelease entries", () => {
  const product = {
    id: "rust",
    category: "toolchain",
    url: "https://example.invalid/rust.json",
  };
  const cycles = [
    { cycle: "1.96", latest: "1.96.0" },
    { cycle: "1.97", latest: "1.97.0-beta.1" },
    { cycle: "1.98", prerelease: true },
  ];

  const selected = lifecycleCycles(product, cycles);

  expect(selected).toHaveLength(1);
  expect(jsonString(selected[0], "cycle")).toBe("1.96");
});
