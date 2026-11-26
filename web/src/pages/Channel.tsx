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
        composer={{ channel, placeholder: `Message #${channel}` }}
        emptyTitle={`Nothing in #${channel} yet`}
        label={`#${channel}`}
      />
    </>
  );
}

/** "# name" with the topic inline, truncated (full text in the tooltip). */
function ChannelHeader({ name, topic }: { name: string; topic?: string }) {
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-rule px-5 max-sm:px-3">
      <h1 className="flex shrink-0 items-baseline gap-1 text-lg font-semibold tracking-tight text-ink">
        <span aria-hidden className="font-normal text-faint">
          #
        </span>
        <span className="sr-only">Channel </span>
        {name}
      </h1>
      {topic && (
        <p title={topic} className="min-w-0 truncate text-[13px] text-muted">
          <span className="sr-only">Topic: </span>
          {topic}
        </p>
      )}
    </header>
  );
}
