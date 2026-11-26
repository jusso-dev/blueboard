/**
 * Curated emoji set in Slack's picker categories. One line per emoji: `<emoji> <shortcode>[,<alias>…] [keyword…]`.
 * The first shortcode is the primary one (shown in the picker preview and in reaction tooltips). Hand-written on
 * purpose: about 600 common emoji cover chat and reactions without a dependency or a 200 KB table.
 */
export const CATEGORY_DATA: { id: string; label: string; lines: string }[] = [
  {
    id: "people",
    label: "Smileys & People",
    lines: `
😀 grinning smile happy
😃 smiley happy joy
😄 smile happy joy laugh
😁 grin happy smile
😆 laughing,satisfied happy laugh
😅 sweat_smile relief nervous phew
🤣 rolling_on_the_floor_laughing,rofl laugh lol
😂 joy laugh tears lol
🙂 slightly_smiling_face smile
🙃 upside_down_face sarcasm silly
😉 wink flirt
😊 blush smile proud
😇 innocent angel halo
🥰 smiling_face_with_3_hearts love crush
😍 heart_eyes love crush
🤩 star-struck,star_struck wow amazing
😘 kissing_heart kiss
☺️ relaxed smile
😋 yum tasty delicious
😛 stuck_out_tongue tongue
😜 stuck_out_tongue_winking_eye silly
🤪 zany_face crazy goofy
🤑 money_mouth_face rich
🤗 hugging_face,hugs hug
🤭 face_with_hand_over_mouth oops giggle
🤫 shushing_face quiet secret
🤔 thinking_face,thinking hmm consider
🫡 saluting_face,salute respect ack roger
🤐 zipper_mouth_face secret quiet
🤨 face_with_raised_eyebrow skeptical suspicious
😐 neutral_face meh
😑 expressionless blank
😶 no_mouth silent
😏 smirk smug
😒 unamused meh
🙄 face_with_rolling_eyes,eyeroll whatever
😬 grimacing awkward yikes
😮‍💨 face_exhaling sigh relief
😌 relieved calm
😔 pensive sad
😪 sleepy tired
😴 sleeping zzz tired
😷 mask sick ill
🤢 nauseated_face sick
🤮 face_vomiting sick
🥵 hot_face heat
🥶 cold_face freezing
😵 dizzy_face dazed
😵‍💫 face_with_spiral_eyes confused
🤯 exploding_head,mind_blown shocked
🤠 face_with_cowboy_hat,cowboy yeehaw
🥳 partying_face party celebrate birthday
😎 sunglasses cool
🤓 nerd_face geek
🧐 face_with_monocle inspect investigate
😕 confused unsure
😟 worried nervous
🙁 slightly_frowning_face sad
😮 open_mouth surprise wow
😲 astonished shocked
😳 flushed embarrassed
🥺 pleading_face please puppy
🥹 face_holding_back_tears grateful
😦 frowning shocked
😨 fearful scared
😰 cold_sweat nervous anxious
😥 disappointed_relieved phew
😢 cry sad tear
😭 sob cry sad
😱 scream horror shocked
😞 disappointed sad
😓 sweat stress
😩 weary tired
😫 tired_face tired
🥱 yawning_face bored tired
😡 rage angry
😠 angry mad
🤬 face_with_symbols_on_mouth swearing cursing
😈 smiling_imp devil evil
💀 skull dead dying
☠️ skull_and_crossbones danger poison pirate
💩 hankey,poop,shit
🤡 clown_face clown
👻 ghost halloween boo
👽 alien ufo
👾 space_invader game alien
🤖 robot_face,robot bot agent ai automation
🙈 see_no_evil monkey
🙉 hear_no_evil monkey
🙊 speak_no_evil monkey
💋 kiss lips
💖 sparkling_heart love
💔 broken_heart sad
❤️‍🔥 heart_on_fire passion
❤️ heart love like
🧡 orange_heart love
💛 yellow_heart love
💚 green_heart love
💙 blue_heart love
💜 purple_heart love
🖤 black_heart love
🤍 white_heart love
💯 100 perfect score hundred
💥 boom,collision explosion bang
💫 dizzy star
💨 dash fast wind
💬 speech_balloon comment chat
💭 thought_balloon thinking
💤 zzz sleep
👋 wave hello hi bye
✋ hand,raised_hand stop high_five
👌 ok_hand okay perfect
✌️ v peace victory
🤞 crossed_fingers,hand_with_index_and_middle_fingers_crossed luck hope
👈 point_left left
👉 point_right right
👆 point_up_2 up
👇 point_down down
☝️ point_up up
👍 thumbsup,+1 yes agree approve like ok good
👎 thumbsdown,-1 no disagree dislike bad
✊ fist,raised_fist power
👊 facepunch,punch fist_bump
👏 clap applause bravo
🙌 raised_hands hooray celebrate
🫶 heart_hands love
🤝 handshake deal agreement
🙏 pray please thanks hope
💪 muscle strong flex
🧠 brain smart think
👀 eyes look watching seen looking
🧑 adult person
👨 man
🧔 bearded_person beard
👩 woman
🙋 raising_hand question me
🙇 bow sorry thanks
🤦 face_palm,facepalm ugh
🤷 shrug dunno whatever
🧑‍💻 technologist developer coder hacker
🧑‍🔬 scientist research
🕵️ sleuth_or_spy,detective investigate
🥷 ninja stealth
🦸 superhero hero
🏃 runner,running run
🗣️ speaking_head_in_silhouette,speaking_head speak
👤 bust_in_silhouette user person
👥 busts_in_silhouette users team
🫂 people_hugging hug
`,
  },
  {
    id: "nature",
    label: "Nature",
    lines: `
🐶 dog puppy pet
🐱 cat kitten pet
🐰 rabbit bunny
🦊 fox_face fox
🐻 bear
🐼 panda_face panda
🐨 koala australia
🐯 tiger
🦁 lion_face,lion
🐮 cow
🐷 pig
🐸 frog
🐵 monkey_face monkey
🐒 monkey
🐔 chicken
🐧 penguin linux
🐦 bird
🐤 baby_chick chick
🦆 duck
🦉 owl wise
🦇 bat
🐺 wolf
🐴 horse
🦄 unicorn_face,unicorn
🐝 bee,honeybee
🐛 bug insect defect issue
🦋 butterfly
🐞 ladybug,lady_beetle insect
🐜 ant
🕷️ spider
🕸️ spider_web web
🐢 turtle slow
🐍 snake python
🐙 octopus
🦀 crab rust
🐟 fish
🐳 whale docker
🦈 shark
🦘 kangaroo australia
🐑 sheep
🦜 parrot
🐾 feet,paw_prints
🐉 dragon
🌵 cactus
🎄 christmas_tree
🌲 evergreen_tree tree
🌳 deciduous_tree tree
🌴 palm_tree tree
🌱 seedling plant grow
🌿 herb plant
🍀 four_leaf_clover luck
🍁 maple_leaf canada
🍂 fallen_leaf autumn
🍃 leaves
🍄 mushroom
🌷 tulip flower
🌹 rose flower
🌸 cherry_blossom flower
🌻 sunflower flower
💐 bouquet flowers
🌙 crescent_moon moon night
⭐ star
🌟 star2 glowing
✨ sparkles shiny new magic
⚡ zap lightning fast power
🔥 fire hot lit burn flame
🌈 rainbow
☀️ sunny sun weather
⛅ partly_sunny weather
☁️ cloud weather
🌧️ rain_cloud rain weather
❄️ snowflake cold winter
🌊 ocean wave water
💧 droplet water
🌏 earth_asia globe world australia
`,
  },
  {
    id: "food",
    label: "Food & Drink",
    lines: `
🍏 green_apple fruit
🍎 apple fruit
🍋 lemon fruit
🍌 banana fruit
🍉 watermelon fruit
🍓 strawberry fruit
🍑 peach fruit
🍍 pineapple fruit
🍅 tomato
🥑 avocado
🥔 potato
🥕 carrot
🌽 corn
🌶️ hot_pepper chili spicy
🥦 broccoli
🍞 bread toast
🥐 croissant
🧀 cheese_wedge,cheese
🥚 egg
🥞 pancakes breakfast
🥓 bacon breakfast
🍔 hamburger burger
🍟 fries chips
🍕 pizza
🥪 sandwich lunch
🌮 taco
🥗 green_salad salad
🍝 spaghetti pasta
🍜 ramen noodles
🍣 sushi
🍱 bento lunch
🥟 dumpling
🍦 icecream
🍩 doughnut donut
🍪 cookie biscuit
🎂 birthday cake
🍰 cake
🧁 cupcake
🍫 chocolate_bar chocolate
🍬 candy lolly
☕ coffee cafe espresso tea
🍵 tea
🥤 cup_with_straw drink
🍺 beer
🍻 beers cheers
🥂 clinking_glasses champagne cheers
🍷 wine_glass wine
🍽️ knife_fork_plate dinner
`,
  },
  {
    id: "activity",
    label: "Activity",
    lines: `
⚽ soccer football
🏀 basketball
🏈 football
⚾ baseball
🎾 tennis
🎱 8ball billiards pool
🏏 cricket_bat_and_ball cricket
⛳ golf
🎣 fishing_pole_and_fish fishing phishing
🏆 trophy win award champion
🥇 first_place_medal gold winner
🥈 second_place_medal silver
🥉 third_place_medal bronze
🏅 sports_medal medal
🎖️ medal military
🎨 art paint palette design
🎬 clapper film movie action
🎤 microphone sing karaoke
🎧 headphones music
🎸 guitar
🎲 game_die dice random
♟️ chess_pawn chess strategy
🎯 dart target bullseye goal
🎮 video_game gaming controller
🧩 jigsaw puzzle piece
🎉 tada party celebrate hooray congrats
🎊 confetti_ball celebrate
🎈 balloon party
🎁 gift present
🎆 fireworks celebrate
`,
  },
  {
    id: "travel",
    label: "Travel & Places",
    lines: `
🚗 car,red_car
🚕 taxi
🚌 bus
🚓 police_car police
🚑 ambulance emergency
🚒 fire_engine
🚚 truck delivery
🚲 bike bicycle
🚨 rotating_light alert alarm siren incident emergency
🚧 construction wip roadwork
⚓ anchor
⛵ boat,sailboat
🚢 ship
✈️ airplane plane flight travel
🚁 helicopter
🚀 rocket launch ship deploy fast
🛸 flying_saucer ufo
🛰️ satellite space
🗺️ world_map map
🧭 compass navigation
⛰️ mountain
🏕️ camping
🏠 house home
🏢 office building work
🏥 hospital
🏦 bank
🏨 hotel
🏫 school
🏭 factory
⛺ tent camping
🏙️ cityscape city
🌅 sunrise morning
⛽ fuelpump fuel petrol
🛑 octagonal_sign stop
⏳ hourglass_flowing_sand wait loading
⌛ hourglass time
⏰ alarm_clock alarm
⏱️ stopwatch timer
`,
  },
  {
    id: "objects",
    label: "Objects",
    lines: `
⌚ watch time
📱 iphone phone mobile
💻 computer laptop
⌨️ keyboard
🖥️ desktop_computer desktop
💾 floppy_disk save
📷 camera photo
📺 tv television
☎️ phone,telephone call
📞 telephone_receiver call
📟 pager oncall
🔋 battery
🔌 electric_plug plug power
💡 bulb idea light
🧯 fire_extinguisher
🗑️ wastebasket trash delete bin
💸 money_with_wings spend
💵 dollar money cash
💳 credit_card card payment
⚖️ scales justice balance law
🧰 toolbox tools
🔧 wrench tool fix
🔨 hammer tool build
🛠️ hammer_and_wrench tools fix build
⚙️ gear settings config
🧱 bricks wall firewall
⛓️ chains chain
🧲 magnet
💣 bomb explosive
🗡️ dagger_knife,dagger
⚔️ crossed_swords fight
🛡️ shield defence defense protect security
🔬 microscope science investigate
🩹 adhesive_bandage bandage fix patch
🧬 dna genetics
🦠 microbe virus germ malware
🧪 test_tube test experiment lab
🧹 broom cleanup sweep
🔑 key password secret
✉️ email,envelope mail
📧 e-mail email
📤 outbox_tray send upload
📥 inbox_tray receive download
📦 package box parcel
📝 memo,pencil note write
📄 page_facing_up document file
📊 bar_chart chart stats
📈 chart_with_upwards_trend up graph growth
📉 chart_with_downwards_trend down graph decline
📆 calendar date
📋 clipboard checklist copy
📁 file_folder folder
📂 open_file_folder folder
📰 newspaper news
📚 books library read
📖 book,open_book read
🔖 bookmark
🏷️ label tag
🔗 link url chain
📎 paperclip attachment
📌 pushpin pin
📍 round_pushpin location pin
✂️ scissors cut
✏️ pencil2 edit
🔍 mag search find investigate
🔎 mag_right search find
🔐 closed_lock_with_key secure
🔒 lock secure locked private
🔓 unlock open unlocked
🔔 bell notification alert
🔕 no_bell mute silent
📣 mega announcement megaphone
📢 loudspeaker announcement
🔇 mute silent
📡 satellite_antenna signal
🪪 identification_card id badge
`,
  },
  {
    id: "symbols",
    label: "Symbols",
    lines: `
✅ white_check_mark done yes complete approved ok
✔️ heavy_check_mark check done
❌ x no wrong cancel fail
➕ heavy_plus_sign plus add
➖ heavy_minus_sign minus
❓ question help why
❗ exclamation,heavy_exclamation_mark important
⚠️ warning caution alert danger
⛔ no_entry stop forbidden blocked
🚫 no_entry_sign forbidden prohibited block deny
♻️ recycle reuse
🆗 ok okay
🆕 new fresh
🆘 sos help emergency
🆔 id identity
🔴 red_circle critical high
🟠 large_orange_circle medium
🟡 large_yellow_circle warning low
🟢 large_green_circle good online
🔵 large_blue_circle,blue_circle info
⚫ black_circle
⚪ white_circle
🔶 large_orange_diamond
🔷 large_blue_diamond
🔺 small_red_triangle up
🔻 small_red_triangle_down down
⬆️ arrow_up up
⬇️ arrow_down down
⬅️ arrow_left left back
➡️ arrow_right right next
↩️ leftwards_arrow_with_hook undo reply
🔄 arrows_counterclockwise refresh sync retry
🔁 repeat loop
🔀 twisted_rightwards_arrows shuffle merge
▶️ arrow_forward play
⏸️ double_vertical_bar pause
⏹️ black_square_for_stop stop
*️⃣ keycap_star
1️⃣ one
2️⃣ two
3️⃣ three
ℹ️ information_source info
☢️ radioactive_sign radiation
☣️ biohazard_sign hazard
🎵 musical_note music
🎶 notes music
📶 signal_strength network
♾️ infinity forever
`,
  },
  {
    id: "flags",
    label: "Flags",
    lines: `
🏁 checkered_flag finish done race
🚩 triangular_flag_on_post red_flag warning
🏳️ waving_white_flag surrender
🏳️‍🌈 rainbow-flag pride
🏴‍☠️ pirate_flag
🇦🇺 flag-au,au australia
🇳🇿 flag-nz,nz new_zealand
🇺🇸 flag-us,us usa america
🇬🇧 flag-gb,gb,uk united_kingdom britain
🇨🇦 flag-ca,ca canada
🇫🇷 flag-fr,fr france
🇩🇪 flag-de,de germany
🇮🇹 flag-it,it italy
🇪🇸 flag-es,es spain
🇳🇱 flag-nl netherlands
🇸🇪 flag-se sweden
🇨🇭 flag-ch switzerland
🇺🇦 flag-ua ukraine
🇯🇵 flag-jp,jp japan
🇰🇷 flag-kr,kr korea
🇨🇳 flag-cn,cn china
🇮🇳 flag-in india
🇸🇬 flag-sg singapore
🇧🇷 flag-br brazil
🇿🇦 flag-za south_africa
🇪🇺 flag-eu,eu european_union
`,
  },
];
