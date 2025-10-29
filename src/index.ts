import { Octokit } from "@octokit/core"
import { paginateRest } from "@octokit/plugin-paginate-rest"

const PaginatedOctokit = Octokit.plugin(paginateRest)

const octokit = new PaginatedOctokit({
  auth: Bun.env.GITHUB_TOKEN,
})

const fetchThreatFeed = async (packages: Bun.Security.Package[]) => {
  return octokit.paginate("GET /advisories", {
    ecosystem: "npm",
    per_page: 100,
    affects: packages.map((p) => [p.name, p.version].join("@")),
    sort: "updated",
    direction: "desc",
  })
}

export const scanner: Bun.Security.Scanner = {
  version: "1",
  async scan({ packages }) {
    const feed = await fetchThreatFeed(packages)

    // Iterate over reported threats and return an array of advisories. This
    // could be longer, shorter or equal length of the input packages array.
    // Whatever you return will be shown to the user.

    const results: Bun.Security.Advisory[] = []

    for (const item of feed) {
      // Advisory levels control installation behavior:
      // - All advisories are always shown to the user regardless of level
      // - Fatal: Installation stops immediately (e.g., backdoors, botnets)
      // - Warning: User prompted in TTY, auto-cancelled in non-TTY (e.g., protestware, adware)

      if (item.type === "unreviewed") continue

      const isFatal = item.type === "malware" || item.severity === "critical"

      for (const vulnerability of item.vulnerabilities || []) {
        if (vulnerability.package?.ecosystem !== "npm") continue

        results.push({
          level: isFatal ? "fatal" : "warn",
          description: item.description,
          package: vulnerability.package?.name || item.ghsa_id,
          url: item.html_url,
        })
      }

      results.push({
        level: isFatal ? "fatal" : "warn",
        package: item.ghsa_id,
        url: item.html_url,
        description: item.description,
      })
    }

    // Return an empty array if there are no advisories!
    return results
  },
}
