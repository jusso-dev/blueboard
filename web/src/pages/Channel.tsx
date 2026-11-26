import { useParams } from "react-router";
import { Feed } from "../components/feed";
import { useLiveQuery, type Channel } from "../lib/api";

export default function ChannelPage() {
  const { name: channel = "incidents" } = useParams();
  const { data: channels } = useLiveQuery<Channel[]>("/channels");
  const topic = channels?.find((c) => c.name === channel)?.topic;
  return (
    <>
      <ChannelHeader name={channel} topic={topic} />
      <Feed
        query={`channel=${encodeURIComponent(channel)}&roots_only=true`}
        composer={{ channel, placeholder: channel === "general" ? "Message #general (try @mentions or /giphy)" : `Message #${channel}` }}
        emptyTitle={channel === "general" ? "Welcome to #general" : `Nothing in #${channel} yet`}
        emptyBody={
          channel === "general"
            ? "Team chat, shift handovers, and everyday SOC discussion. Type @ to mention someone or /giphy to drop a GIF."
            : undefined
        }
        label={`#${channel}`}
      />
    </>
  );
}

/** Shared header rhythm; long channel names and topics wrap within the viewport. */
function ChannelHeader({ name, topic }: { name: string; topic?: string }) {
  return (
    <header className="flex min-h-14 shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-rule px-6 py-3 max-sm:px-4">
      <h1 className="flex min-w-0 items-baseline gap-1 text-title font-semibold tracking-tight text-ink">
        <span aria-hidden className="font-normal text-faint">
          #
        </span>
        <span className="sr-only">Channel </span>
        {name}
      </h1>
      {topic && (
        <p title={topic} className="min-w-0 flex-1 basis-48 text-ui text-muted [overflow-wrap:anywhere]">
          <span className="sr-only">Topic: </span>
          {topic}
        </p>
      )}
    </header>
  );
}
