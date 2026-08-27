#!/usr/bin/env python3
"""Record hashes and counts for a persisted Spectron translation checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manual-anchors", type=Path)
    parser.add_argument("--manual-verification", type=Path)
    parser.add_argument("--network-anchors", type=Path)
    parser.add_argument("--network-verification", type=Path)
    parser.add_argument("--core-anchors", type=Path)
    parser.add_argument("--core-verification", type=Path)
    parser.add_argument("--runtime-path-anchors", type=Path)
    parser.add_argument("--runtime-path-verification", type=Path)
    parser.add_argument("--update-protocol-anchors", type=Path)
    parser.add_argument("--update-protocol-verification", type=Path)
    parser.add_argument("--client-action-anchors", type=Path)
    parser.add_argument("--client-action-verification", type=Path)
    parser.add_argument("--client-outbound-anchors", type=Path)
    parser.add_argument("--client-outbound-verification", type=Path)
    parser.add_argument("--resource-anchors", type=Path)
    parser.add_argument("--resource-verification", type=Path)
    parser.add_argument("--script-bridge-anchors", type=Path)
    parser.add_argument("--script-bridge-verification", type=Path)
    parser.add_argument("--client-request-anchors", type=Path)
    parser.add_argument("--client-request-verification", type=Path)
    parser.add_argument("--client-inbound-anchors", type=Path)
    parser.add_argument("--client-inbound-verification", type=Path)
    parser.add_argument("--login-helper-anchors", type=Path)
    parser.add_argument("--login-helper-verification", type=Path)
    parser.add_argument("--parse-wrapper-anchors", type=Path)
    parser.add_argument("--parse-wrapper-verification", type=Path)
    parser.add_argument("--lookup-helper-anchors", type=Path)
    parser.add_argument("--lookup-helper-verification", type=Path)
    parser.add_argument("--connection-helper-anchors", type=Path)
    parser.add_argument("--connection-helper-verification", type=Path)
    parser.add_argument("--client-state-helper-anchors", type=Path)
    parser.add_argument("--client-state-helper-verification", type=Path)
    parser.add_argument("--connection-state-anchors", type=Path)
    parser.add_argument("--connection-state-verification", type=Path)
    parser.add_argument("--http-request-anchors", type=Path)
    parser.add_argument("--http-request-verification", type=Path)
    parser.add_argument("--socket-state-anchors", type=Path)
    parser.add_argument("--socket-state-verification", type=Path)
    parser.add_argument("--http-request-state-anchors", type=Path)
    parser.add_argument("--http-request-state-verification", type=Path)
    parser.add_argument("--npc-helper-anchors", type=Path)
    parser.add_argument("--npc-helper-verification", type=Path)
    parser.add_argument("--html-atom-anchors", type=Path)
    parser.add_argument("--html-atom-verification", type=Path)
    parser.add_argument("--player-helper-anchors", type=Path)
    parser.add_argument("--player-helper-verification", type=Path)
    parser.add_argument("--input-window-anchors", type=Path)
    parser.add_argument("--input-window-verification", type=Path)
    parser.add_argument("--visual-helper-anchors", type=Path)
    parser.add_argument("--visual-helper-verification", type=Path)
    parser.add_argument("--script-runtime-anchors", type=Path)
    parser.add_argument("--script-runtime-verification", type=Path)
    parser.add_argument("--core-helper-anchors", type=Path)
    parser.add_argument("--core-helper-verification", type=Path)
    parser.add_argument("--render-gui-anchors", type=Path)
    parser.add_argument("--render-gui-verification", type=Path)
    parser.add_argument("--json-folder-anchors", type=Path)
    parser.add_argument("--json-folder-verification", type=Path)
    parser.add_argument("--resource-object-anchors", type=Path)
    parser.add_argument("--resource-object-verification", type=Path)
    parser.add_argument("--script-machine-anchors", type=Path)
    parser.add_argument("--script-machine-verification", type=Path)
    parser.add_argument("--script-space-anchors", type=Path)
    parser.add_argument("--script-space-verification", type=Path)
    parser.add_argument("--script-execution-anchors", type=Path)
    parser.add_argument("--script-execution-verification", type=Path)
    parser.add_argument("--script-dispatch-anchors", type=Path)
    parser.add_argument("--script-dispatch-verification", type=Path)
    parser.add_argument("--script-scheduler-anchors", type=Path)
    parser.add_argument("--script-scheduler-verification", type=Path)
    parser.add_argument("--event-object-anchors", type=Path)
    parser.add_argument("--event-object-verification", type=Path)
    parser.add_argument("--script-action-anchors", type=Path)
    parser.add_argument("--script-action-verification", type=Path)
    parser.add_argument("--stack-entry-anchors", type=Path)
    parser.add_argument("--stack-entry-verification", type=Path)
    parser.add_argument("--machine-helper-anchors", type=Path)
    parser.add_argument("--machine-helper-verification", type=Path)
    parser.add_argument("--array-mutation-anchors", type=Path)
    parser.add_argument("--array-mutation-verification", type=Path)
    parser.add_argument("--string-search-anchors", type=Path)
    parser.add_argument("--string-search-verification", type=Path)
    parser.add_argument("--string-helper-anchors", type=Path)
    parser.add_argument("--string-helper-verification", type=Path)
    parser.add_argument("--variable-construction-anchors", type=Path)
    parser.add_argument("--variable-construction-verification", type=Path)
    parser.add_argument("--script-object-anchors", type=Path)
    parser.add_argument("--script-object-verification", type=Path)
    parser.add_argument("--script-state-anchors", type=Path)
    parser.add_argument("--script-state-verification", type=Path)
    parser.add_argument("--execution-dispatch-anchors", type=Path)
    parser.add_argument("--execution-dispatch-verification", type=Path)
    parser.add_argument("--tokenizer-anchors", type=Path)
    parser.add_argument("--tokenizer-verification", type=Path)
    parser.add_argument("--script-executor-anchors", type=Path)
    parser.add_argument("--script-executor-verification", type=Path)
    parser.add_argument("--script-property-anchors", type=Path)
    parser.add_argument("--script-property-verification", type=Path)
    parser.add_argument("--script-universe-anchors", type=Path)
    parser.add_argument("--script-universe-verification", type=Path)
    parser.add_argument("--static-json-tiles-anchors", type=Path)
    parser.add_argument("--static-json-tiles-verification", type=Path)
    parser.add_argument("--tiles-update-anchors", type=Path)
    parser.add_argument("--tiles-update-verification", type=Path)
    parser.add_argument("--particle-anchors", type=Path)
    parser.add_argument("--particle-verification", type=Path)
    parser.add_argument("--showimg-anchors", type=Path)
    parser.add_argument("--showimg-verification", type=Path)
    parser.add_argument("--showimg-property-anchors", type=Path)
    parser.add_argument("--showimg-property-verification", type=Path)
    parser.add_argument("--showimg-residual-anchors", type=Path)
    parser.add_argument("--showimg-residual-verification", type=Path)
    parser.add_argument("--server-object-scalar-anchors", type=Path)
    parser.add_argument("--server-object-scalar-verification", type=Path)
    parser.add_argument("--compression-anchors", type=Path)
    parser.add_argument("--compression-verification", type=Path)
    parser.add_argument("--files-anchors", type=Path)
    parser.add_argument("--files-verification", type=Path)
    parser.add_argument("--encryption-anchors", type=Path)
    parser.add_argument("--encryption-verification", type=Path)
    parser.add_argument("--tlist-anchors", type=Path)
    parser.add_argument("--tlist-verification", type=Path)
    parser.add_argument("--sounds-anchors", type=Path)
    parser.add_argument("--sounds-verification", type=Path)
    parser.add_argument("--hash-container-anchors", type=Path)
    parser.add_argument("--hash-container-verification", type=Path)
    parser.add_argument("--tstring-anchors", type=Path)
    parser.add_argument("--tstring-verification", type=Path)
    parser.add_argument("--tstring-clear-anchors", type=Path)
    parser.add_argument("--tstring-clear-verification", type=Path)
    parser.add_argument("--static-clear-anchors", type=Path)
    parser.add_argument("--static-clear-verification", type=Path)
    parser.add_argument("--http-request-receive-anchors", type=Path)
    parser.add_argument("--http-request-receive-verification", type=Path)
    parser.add_argument("--server-list-connection-anchors", type=Path)
    parser.add_argument("--server-list-connection-verification", type=Path)
    parser.add_argument("--server-list-state-anchors", type=Path)
    parser.add_argument("--server-list-state-verification", type=Path)
    parser.add_argument("--http-request-cleanup-anchors", type=Path)
    parser.add_argument("--http-request-cleanup-verification", type=Path)
    parser.add_argument("--tsocket-residual-anchors", type=Path)
    parser.add_argument("--tsocket-residual-verification", type=Path)
    parser.add_argument("--game-environment-anchors", type=Path)
    parser.add_argument("--game-environment-verification", type=Path)
    parser.add_argument("--client-environment-graphics-anchors", type=Path)
    parser.add_argument("--client-environment-graphics-verification", type=Path)
    parser.add_argument("--client-environment-static-clear-anchors", type=Path)
    parser.add_argument("--client-environment-static-clear-verification", type=Path)
    parser.add_argument("--client-environment-restart-state-anchors", type=Path)
    parser.add_argument("--client-environment-restart-state-verification", type=Path)
    parser.add_argument("--particle-emitter-anchors", type=Path)
    parser.add_argument("--particle-emitter-verification", type=Path)
    parser.add_argument("--particle-emitter-script-vars-anchors", type=Path)
    parser.add_argument("--particle-emitter-script-vars-verification", type=Path)
    parser.add_argument("--resource-link-lists-anchors", type=Path)
    parser.add_argument("--resource-link-lists-verification", type=Path)
    parser.add_argument("--clear-cur-anis-anchors", type=Path)
    parser.add_argument("--clear-cur-anis-verification", type=Path)
    parser.add_argument("--options-window-position-anchors", type=Path)
    parser.add_argument("--options-window-position-verification", type=Path)
    parser.add_argument("--server-animation-anchors", type=Path)
    parser.add_argument("--server-animation-verification", type=Path)
    parser.add_argument("--player-lifecycle-anchors", type=Path)
    parser.add_argument("--player-lifecycle-verification", type=Path)
    parser.add_argument("--player-emoticon-anchors", type=Path)
    parser.add_argument("--player-emoticon-verification", type=Path)
    parser.add_argument("--player-level-entry-anchors", type=Path)
    parser.add_argument("--player-level-entry-verification", type=Path)
    parser.add_argument("--player-side-level-anchors", type=Path)
    parser.add_argument("--player-side-level-verification", type=Path)
    parser.add_argument("--player-map-position-anchors", type=Path)
    parser.add_argument("--player-map-position-verification", type=Path)
    parser.add_argument("--player-link-traversal-anchors", type=Path)
    parser.add_argument("--player-link-traversal-verification", type=Path)
    parser.add_argument("--player-weapon-state-anchors", type=Path)
    parser.add_argument("--player-weapon-state-verification", type=Path)
    parser.add_argument("--player-visual-setter-anchors", type=Path)
    parser.add_argument("--player-visual-setter-verification", type=Path)
    parser.add_argument("--player-movement-anchors", type=Path)
    parser.add_argument("--player-movement-verification", type=Path)
    parser.add_argument("--server-player-state-anchors", type=Path)
    parser.add_argument("--server-player-state-verification", type=Path)
    parser.add_argument("--server-npc-state-anchors", type=Path)
    parser.add_argument("--server-npc-state-verification", type=Path)
    parser.add_argument("--npc-accessor-anchors", type=Path)
    parser.add_argument("--npc-accessor-verification", type=Path)
    parser.add_argument("--npc-destructor-anchors", type=Path)
    parser.add_argument("--npc-destructor-verification", type=Path)
    parser.add_argument("--server-level-property-anchors", type=Path)
    parser.add_argument("--server-level-property-verification", type=Path)
    parser.add_argument("--server-level-interaction-anchors", type=Path)
    parser.add_argument("--server-level-interaction-verification", type=Path)
    parser.add_argument("--server-level-lifecycle-anchors", type=Path)
    parser.add_argument("--server-level-lifecycle-verification", type=Path)
    parser.add_argument("--server-level-side-helpers-anchors", type=Path)
    parser.add_argument("--server-level-side-helpers-verification", type=Path)
    parser.add_argument("--server-level-storage-anchors", type=Path)
    parser.add_argument("--server-level-storage-verification", type=Path)
    parser.add_argument("--hidden-testnpc-anchors", type=Path)
    parser.add_argument("--hidden-testnpc-verification", type=Path)
    parser.add_argument("--level-map-lookup-anchors", type=Path)
    parser.add_argument("--level-map-lookup-verification", type=Path)
    parser.add_argument("--gani-constructor-anchors", type=Path)
    parser.add_argument("--gani-constructor-verification", type=Path)
    parser.add_argument("--gani-helper-anchors", type=Path)
    parser.add_argument("--gani-helper-verification", type=Path)
    parser.add_argument("--gani-runtime-anchors", type=Path)
    parser.add_argument("--gani-runtime-verification", type=Path)
    parser.add_argument("--gani-render-anchors", type=Path)
    parser.add_argument("--gani-render-verification", type=Path)
    parser.add_argument("--gani-frame-playback-anchors", type=Path)
    parser.add_argument("--gani-frame-playback-verification", type=Path)
    parser.add_argument("--gani-lifecycle-anchors", type=Path)
    parser.add_argument("--gani-lifecycle-verification", type=Path)
    parser.add_argument("--tplayer-core-anchors", type=Path)
    parser.add_argument("--tplayer-core-verification", type=Path)
    parser.add_argument("--resource-parser-anchors", type=Path)
    parser.add_argument("--resource-parser-verification", type=Path)
    parser.add_argument("--static-utility-anchors", type=Path)
    parser.add_argument("--static-utility-verification", type=Path)
    parser.add_argument("--font-bitmap-anchors", type=Path)
    parser.add_argument("--font-bitmap-verification", type=Path)
    parser.add_argument("--mng-animation-anchors", type=Path)
    parser.add_argument("--mng-animation-verification", type=Path)
    parser.add_argument("--script-machine-tail-anchors", type=Path)
    parser.add_argument("--script-machine-tail-verification", type=Path)
    parser.add_argument("--script-stream-profile-anchors", type=Path)
    parser.add_argument("--script-stream-profile-verification", type=Path)
    parser.add_argument("--ani-lexer-anchors", type=Path)
    parser.add_argument("--ani-lexer-verification", type=Path)
    parser.add_argument("--number-array-string-anchors", type=Path)
    parser.add_argument("--number-array-string-verification", type=Path)
    parser.add_argument("--client-environment-clock-anchors", type=Path)
    parser.add_argument("--client-environment-clock-verification", type=Path)
    parser.add_argument("--client-var-core-anchors", type=Path)
    parser.add_argument("--client-var-core-verification", type=Path)
    parser.add_argument("--tstringlist-comma-anchors", type=Path)
    parser.add_argument("--tstringlist-comma-verification", type=Path)
    parser.add_argument("--tstringlist-extended-anchors", type=Path)
    parser.add_argument("--tstringlist-extended-verification", type=Path)
    parser.add_argument("--hash-family-anchors", type=Path)
    parser.add_argument("--hash-family-verification", type=Path)
    parser.add_argument("--options-anchors", type=Path)
    parser.add_argument("--options-verification", type=Path)
    parser.add_argument("--texture-anchors", type=Path)
    parser.add_argument("--texture-verification", type=Path)
    parser.add_argument("--drawing-panel-texture-anchors", type=Path)
    parser.add_argument("--drawing-panel-texture-verification", type=Path)
    parser.add_argument("--draw-texture-anchors", type=Path)
    parser.add_argument("--draw-texture-verification", type=Path)
    parser.add_argument("--bitmap-array-holder-anchors", type=Path)
    parser.add_argument("--bitmap-array-holder-verification", type=Path)
    parser.add_argument("--color-manager-anchors", type=Path)
    parser.add_argument("--color-manager-verification", type=Path)
    parser.add_argument("--font-runtime-anchors", type=Path)
    parser.add_argument("--font-runtime-verification", type=Path)
    parser.add_argument("--window-input-anchors", type=Path)
    parser.add_argument("--window-input-verification", type=Path)
    parser.add_argument("--drawing-panel-residual-anchors", type=Path)
    parser.add_argument("--drawing-panel-residual-verification", type=Path)
    parser.add_argument("--image-html-anchors", type=Path)
    parser.add_argument("--image-html-verification", type=Path)
    parser.add_argument("--panel-bitmap-anchors", type=Path)
    parser.add_argument("--panel-bitmap-verification", type=Path)
    parser.add_argument("--gif-decoder-anchors", type=Path)
    parser.add_argument("--gif-decoder-verification", type=Path)
    parser.add_argument("--window-residual-anchors", type=Path)
    parser.add_argument("--window-residual-verification", type=Path)
    parser.add_argument("--sound-runtime-anchors", type=Path)
    parser.add_argument("--sound-runtime-verification", type=Path)
    parser.add_argument("--pixelbuffer-residual-anchors", type=Path)
    parser.add_argument("--pixelbuffer-residual-verification", type=Path)
    parser.add_argument("--pixelbuffer-bitmap-lifecycle-anchors", type=Path)
    parser.add_argument("--pixelbuffer-bitmap-lifecycle-verification", type=Path)
    parser.add_argument("--animation-palette-residual-anchors", type=Path)
    parser.add_argument("--animation-palette-residual-verification", type=Path)
    parser.add_argument("--panel-virtual-renderer-residual-anchors", type=Path)
    parser.add_argument("--panel-virtual-renderer-residual-verification", type=Path)
    parser.add_argument("--dummy-panel-residual-anchors", type=Path)
    parser.add_argument("--dummy-panel-residual-verification", type=Path)
    parser.add_argument("--screen-panel-renderer-residual-anchors", type=Path)
    parser.add_argument("--screen-panel-renderer-residual-verification", type=Path)
    parser.add_argument("--screen-panel-window-gles-residual-anchors", type=Path)
    parser.add_argument("--screen-panel-window-gles-residual-verification", type=Path)
    parser.add_argument("--font-manager-font-residual-anchors", type=Path)
    parser.add_argument("--font-manager-font-residual-verification", type=Path)
    parser.add_argument("--font-options-font-data-residual-anchors", type=Path)
    parser.add_argument("--font-options-font-data-residual-verification", type=Path)
    parser.add_argument("--gui-control-profile-accessor-anchors", type=Path)
    parser.add_argument("--gui-control-profile-accessor-verification", type=Path)
    parser.add_argument("--gui-control-profile-destructor-anchors", type=Path)
    parser.add_argument("--gui-control-profile-destructor-verification", type=Path)
    parser.add_argument("--gui-control-property-residual-anchors", type=Path)
    parser.add_argument("--gui-control-property-residual-verification", type=Path)
    parser.add_argument("--gui-control-virtual-residual-anchors", type=Path)
    parser.add_argument("--gui-control-virtual-residual-verification", type=Path)
    parser.add_argument("--gui-control-event-sizing-residual-anchors", type=Path)
    parser.add_argument("--gui-control-event-sizing-residual-verification", type=Path)
    parser.add_argument("--gui-control-style-bounds-residual-anchors", type=Path)
    parser.add_argument("--gui-control-style-bounds-residual-verification", type=Path)
    parser.add_argument("--gui-control-event-dispatch-residual-anchors", type=Path)
    parser.add_argument("--gui-control-event-dispatch-residual-verification", type=Path)
    parser.add_argument("--gui-control-initialization-residual-anchors", type=Path)
    parser.add_argument("--gui-control-initialization-residual-verification", type=Path)
    parser.add_argument("--gui-control-create-residual-anchors", type=Path)
    parser.add_argument("--gui-control-create-residual-verification", type=Path)
    parser.add_argument("--tsocket-accessor-residual-anchors", type=Path)
    parser.add_argument("--tsocket-accessor-residual-verification", type=Path)
    parser.add_argument("--tsocket-ssl-residual-anchors", type=Path)
    parser.add_argument("--tsocket-ssl-residual-verification", type=Path)
    parser.add_argument("--tsocket-receive-residual-anchors", type=Path)
    parser.add_argument("--tsocket-receive-residual-verification", type=Path)
    parser.add_argument("--tsocket-lifecycle-residual-anchors", type=Path)
    parser.add_argument("--tsocket-lifecycle-residual-verification", type=Path)
    parser.add_argument("--tsocket-host-residual-anchors", type=Path)
    parser.add_argument("--tsocket-host-residual-verification", type=Path)
    parser.add_argument("--tsocket-properties-residual-anchors", type=Path)
    parser.add_argument("--tsocket-properties-residual-verification", type=Path)
    parser.add_argument("--socket-cache-residual-anchors", type=Path)
    parser.add_argument("--socket-cache-residual-verification", type=Path)
    parser.add_argument("--url-cache-residual-anchors", type=Path)
    parser.add_argument("--url-cache-residual-verification", type=Path)
    parser.add_argument("--player-list-residual-anchors", type=Path)
    parser.add_argument("--player-list-residual-verification", type=Path)
    parser.add_argument("--client-thread-residual-anchors", type=Path)
    parser.add_argument("--client-thread-residual-verification", type=Path)
    parser.add_argument("--update-package-accessor-residual-anchors", type=Path)
    parser.add_argument("--update-package-accessor-residual-verification", type=Path)
    parser.add_argument("--update-package-destructor-residual-anchors", type=Path)
    parser.add_argument("--update-package-destructor-residual-verification", type=Path)
    parser.add_argument("--update-package-wrapper-residual-anchors", type=Path)
    parser.add_argument("--update-package-wrapper-residual-verification", type=Path)
    parser.add_argument("--update-package-properties-residual-anchors", type=Path)
    parser.add_argument("--update-package-properties-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-math-string-residual-anchors", type=Path)
    parser.add_argument("--gsfunctions-math-string-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-callback-residual-anchors", type=Path)
    parser.add_argument("--gsfunctions-callback-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-randomstring-residual-anchors", type=Path)
    parser.add_argument("--gsfunctions-randomstring-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-anchors", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v2-anchors", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v2-verification", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v3-anchors", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v3-verification", type=Path)
    parser.add_argument("--gsfunctions-client-boundary-residual-anchors", type=Path)
    parser.add_argument("--gsfunctions-client-boundary-residual-verification", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v4-anchors", type=Path)
    parser.add_argument("--gsfunctions-client-exact-residual-v4-verification", type=Path)
    parser.add_argument("--cyaint-tls-residual-anchors", type=Path)
    parser.add_argument("--cyaint-tls-residual-verification", type=Path)
    parser.add_argument("--cyaint-tls-residual-v2-anchors", type=Path)
    parser.add_argument("--cyaint-tls-residual-v2-verification", type=Path)
    parser.add_argument("--tserverplayer-accessor-anchors", type=Path)
    parser.add_argument("--tserverplayer-accessor-verification", type=Path)
    parser.add_argument("--tplayer-scalar-setter-anchors", type=Path)
    parser.add_argument("--tplayer-scalar-setter-verification", type=Path)
    parser.add_argument("--tplayer-scalar-getter-anchors", type=Path)
    parser.add_argument("--tplayer-scalar-getter-verification", type=Path)
    parser.add_argument("--tplayer-flag-setter-anchors", type=Path)
    parser.add_argument("--tplayer-flag-setter-verification", type=Path)
    parser.add_argument("--tserverplayer-property-block-anchors", type=Path)
    parser.add_argument("--tserverplayer-property-block-verification", type=Path)
    parser.add_argument("--tserverplayer-residual-anchors", type=Path)
    parser.add_argument("--tserverplayer-residual-verification", type=Path)
    parser.add_argument("--tserverplayer-tail-anchors", type=Path)
    parser.add_argument("--tserverplayer-tail-verification", type=Path)
    args = parser.parse_args()

    translation = load(args.map)
    verification = load(args.verification)
    if translation.get("artifact") != "spectron_semantic_function_translation":
        raise ValueError("unexpected translation map artifact")
    if not verification.get("verified"):
        raise ValueError("IDA reopen verification did not pass")
    expected = translation["summary"]["mapped_high_confidence"]
    if verification["high_confidence_match_count"] != expected:
        raise ValueError("verification match count differs from translation map")
    manual = None
    if args.manual_anchors or args.manual_verification:
        if not args.manual_anchors or not args.manual_verification:
            raise ValueError("manual anchors and manual verification must be supplied together")
        manual_document = load(args.manual_anchors)
        manual_verification = load(args.manual_verification)
        if manual_document.get("artifact") != "spectron_manual_translation_anchors_20260826":
            raise ValueError("unexpected manual-anchor artifact")
        if not manual_verification.get("verified"):
            raise ValueError("manual-anchor reopen verification did not pass")
        expected_manual = len(manual_document["anchors"])
        if manual_verification["verified_name_count"] != expected_manual:
            raise ValueError("manual-anchor verification count differs from artifact")
        manual = {
            "anchor_path": str(args.manual_anchors),
            "anchor_sha256": sha256_path(args.manual_anchors),
            "reopen_verification": str(args.manual_verification),
            "anchor_count": expected_manual,
            "verified_name_count": manual_verification["verified_name_count"],
            "reopen_failure_count": manual_verification["failure_count"],
        }
    network = None
    if args.network_anchors or args.network_verification:
        if not args.network_anchors or not args.network_verification:
            raise ValueError("network anchors and network verification must be supplied together")
        network_document = load(args.network_anchors)
        network_verification = load(args.network_verification)
        if network_document.get("artifact") != "spectron_network_manual_translation_anchors_20260826":
            raise ValueError("unexpected network-anchor artifact")
        if not network_verification.get("verified"):
            raise ValueError("network-anchor reopen verification did not pass")
        expected_network = len(network_document["anchors"])
        if network_verification["verified_name_count"] != expected_network:
            raise ValueError("network-anchor verification count differs from artifact")
        network = {
            "anchor_path": str(args.network_anchors),
            "anchor_sha256": sha256_path(args.network_anchors),
            "reopen_verification": str(args.network_verification),
            "anchor_count": expected_network,
            "verified_name_count": network_verification["verified_name_count"],
            "reopen_failure_count": network_verification["failure_count"],
        }
    core = None
    if args.core_anchors or args.core_verification:
        if not args.core_anchors or not args.core_verification:
            raise ValueError("core anchors and core verification must be supplied together")
        core_document = load(args.core_anchors)
        core_verification = load(args.core_verification)
        if core_document.get("artifact") != "spectron_core_manual_translation_anchors_20260826":
            raise ValueError("unexpected core-anchor artifact")
        if not core_verification.get("verified"):
            raise ValueError("core-anchor reopen verification did not pass")
        expected_core = len(core_document["anchors"])
        if core_verification["verified_name_count"] != expected_core:
            raise ValueError("core-anchor verification count differs from artifact")
        core = {
            "anchor_path": str(args.core_anchors),
            "anchor_sha256": sha256_path(args.core_anchors),
            "reopen_verification": str(args.core_verification),
            "anchor_count": expected_core,
            "verified_name_count": core_verification["verified_name_count"],
            "reopen_failure_count": core_verification["failure_count"],
        }
    result = {
        "schema_version": 1,
        "artifact": "spectron_translation_checkpoint_20260826",
        "scope": "persisted high-confidence 1.8-to-Spectron ARM64 semantic labels",
        "network_contacted": False,
        "inputs": {
            "original_binary_sha256": translation["inputs"].get("original_binary_sha256"),
            "spectron_binary_sha256": translation["inputs"].get("spectron_binary_sha256"),
            "translation_map": str(args.map),
            "translation_map_sha256": sha256_path(args.map),
            "reopen_verification": str(args.verification),
        },
        "database": {
            "path": str(args.database),
            "sha256": sha256_path(args.database),
            "format": "packed IDA 9.3 database",
            "close_reopen_verified": True,
            "function_count": verification["function_count"],
            "default_sub_function_count": verification["default_sub_function_count"],
        },
        "translation": {
            "mapped_functions": translation["summary"]["mapped_functions"],
            "high_confidence_applied": translation["summary"]["mapped_high_confidence"],
            "medium_confidence_review_only": translation["summary"]["mapped_medium_confidence"],
            "ambiguous_functions": translation["summary"]["ambiguous_functions"],
            "unmatched_functions": translation["summary"]["unmatched_functions"],
            "unique_spectron_targets": translation["summary"]["unique_spectron_targets"],
            "reopen_failure_count": verification["failure_count"],
        },
        "interpretation": [
            "The saved database contains v18_ analysis labels on the verified high-confidence target functions.",
            "The labels preserve the original 1.8 semantic names while keeping the Spectron address and obfuscated name in the map.",
            "The medium-confidence, ambiguous, and unmatched functions remain review-only and were not silently renamed.",
        ],
    }
    if manual is not None:
        result["manual_anchors"] = manual
        result["interpretation"].append(
            "The second database revision also contains the separately reviewed manual context anchors."
        )
    if network is not None:
        result["network_anchors"] = network
        result["interpretation"].append(
            "The third database revision also contains the separately reviewed connector and socket context anchors."
        )
    if core is not None:
        result["core_anchors"] = core
        result["interpretation"].append(
            "The fourth database revision also contains the separately reviewed resource, rendering, GUI, scripting, and client context anchors."
        )
    runtime_path = None
    if args.runtime_path_anchors or args.runtime_path_verification:
        if not args.runtime_path_anchors or not args.runtime_path_verification:
            raise ValueError(
                "runtime-path anchors and runtime-path verification must be supplied together"
            )
        runtime_path_document = load(args.runtime_path_anchors)
        runtime_path_verification = load(args.runtime_path_verification)
        if runtime_path_document.get("artifact") != "spectron_runtime_path_manual_translation_anchors_20260826":
            raise ValueError("unexpected runtime-path anchor artifact")
        if not runtime_path_verification.get("verified"):
            raise ValueError("runtime-path anchor reopen verification did not pass")
        expected_runtime_path = len(runtime_path_document["anchors"])
        if runtime_path_verification["verified_name_count"] != expected_runtime_path:
            raise ValueError("runtime-path verification count differs from artifact")
        runtime_path = {
            "anchor_path": str(args.runtime_path_anchors),
            "anchor_sha256": sha256_path(args.runtime_path_anchors),
            "reopen_verification": str(args.runtime_path_verification),
            "anchor_count": expected_runtime_path,
            "verified_name_count": runtime_path_verification["verified_name_count"],
            "reopen_failure_count": runtime_path_verification["failure_count"],
        }
    if runtime_path is not None:
        result["runtime_path_anchors"] = runtime_path
        result["interpretation"].append(
            "The fifth database revision also contains the separately reviewed map-entry, file-delivery, script, text-control, and server-list context anchors."
        )
    update_protocol = None
    if args.update_protocol_anchors or args.update_protocol_verification:
        if not args.update_protocol_anchors or not args.update_protocol_verification:
            raise ValueError(
                "update-protocol anchors and update-protocol verification must be supplied together"
            )
        update_protocol_document = load(args.update_protocol_anchors)
        update_protocol_verification = load(args.update_protocol_verification)
        if update_protocol_document.get("artifact") != "spectron_update_protocol_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-protocol anchor artifact")
        if not update_protocol_verification.get("verified"):
            raise ValueError("update-protocol anchor reopen verification did not pass")
        expected_update_protocol = len(update_protocol_document["anchors"])
        if update_protocol_verification["verified_name_count"] != expected_update_protocol:
            raise ValueError("update-protocol verification count differs from artifact")
        update_protocol = {
            "anchor_path": str(args.update_protocol_anchors),
            "anchor_sha256": sha256_path(args.update_protocol_anchors),
            "reopen_verification": str(args.update_protocol_verification),
            "anchor_count": expected_update_protocol,
            "verified_name_count": update_protocol_verification["verified_name_count"],
            "reopen_failure_count": update_protocol_verification["failure_count"],
        }
    if update_protocol is not None:
        result["update_protocol_anchors"] = update_protocol
        result["interpretation"].append(
            "The sixth database revision also contains the separately reviewed download-queue, update-request, server-modify, and image-checksum context anchors."
        )
    client_action = None
    if args.client_action_anchors or args.client_action_verification:
        if not args.client_action_anchors or not args.client_action_verification:
            raise ValueError(
                "client-action anchors and client-action verification must be supplied together"
            )
        client_action_document = load(args.client_action_anchors)
        client_action_verification = load(args.client_action_verification)
        if client_action_document.get("artifact") != "spectron_client_action_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-action anchor artifact")
        if not client_action_verification.get("verified"):
            raise ValueError("client-action anchor reopen verification did not pass")
        expected_client_action = len(client_action_document["anchors"])
        if client_action_verification["verified_name_count"] != expected_client_action:
            raise ValueError("client-action verification count differs from artifact")
        client_action = {
            "anchor_path": str(args.client_action_anchors),
            "anchor_sha256": sha256_path(args.client_action_anchors),
            "reopen_verification": str(args.client_action_verification),
            "anchor_count": expected_client_action,
            "verified_name_count": client_action_verification["verified_name_count"],
            "reopen_failure_count": client_action_verification["failure_count"],
        }
    if client_action is not None:
        result["client_action_anchors"] = client_action
        result["interpretation"].append(
            "The seventh database revision also contains the separately reviewed client action packet serializer anchors."
        )
    client_outbound = None
    if args.client_outbound_anchors or args.client_outbound_verification:
        if not args.client_outbound_anchors or not args.client_outbound_verification:
            raise ValueError(
                "client-outbound anchors and client-outbound verification must be supplied together"
            )
        client_outbound_document = load(args.client_outbound_anchors)
        client_outbound_verification = load(args.client_outbound_verification)
        if client_outbound_document.get("artifact") != "spectron_client_outbound_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-outbound anchor artifact")
        if not client_outbound_verification.get("verified"):
            raise ValueError("client-outbound anchor reopen verification did not pass")
        expected_client_outbound = len(client_outbound_document["anchors"])
        if client_outbound_verification["verified_name_count"] != expected_client_outbound:
            raise ValueError("client-outbound verification count differs from artifact")
        client_outbound = {
            "anchor_path": str(args.client_outbound_anchors),
            "anchor_sha256": sha256_path(args.client_outbound_anchors),
            "reopen_verification": str(args.client_outbound_verification),
            "anchor_count": expected_client_outbound,
            "verified_name_count": client_outbound_verification["verified_name_count"],
            "reopen_failure_count": client_outbound_verification["failure_count"],
        }
    if client_outbound is not None:
        result["client_outbound_anchors"] = client_outbound
        result["interpretation"].append(
            "The eighth database revision also contains the separately reviewed remaining client outbound packet serializer anchors."
        )
    resource = None
    if args.resource_anchors or args.resource_verification:
        if not args.resource_anchors or not args.resource_verification:
            raise ValueError(
                "resource anchors and resource verification must be supplied together"
            )
        resource_document = load(args.resource_anchors)
        resource_verification = load(args.resource_verification)
        if resource_document.get("artifact") != "spectron_resource_manual_translation_anchors_20260826":
            raise ValueError("unexpected resource anchor artifact")
        if not resource_verification.get("verified"):
            raise ValueError("resource anchor reopen verification did not pass")
        expected_resource = len(resource_document["anchors"])
        if resource_verification["verified_name_count"] != expected_resource:
            raise ValueError("resource verification count differs from artifact")
        resource = {
            "anchor_path": str(args.resource_anchors),
            "anchor_sha256": sha256_path(args.resource_anchors),
            "reopen_verification": str(args.resource_verification),
            "anchor_count": expected_resource,
            "verified_name_count": resource_verification["verified_name_count"],
            "reopen_failure_count": resource_verification["failure_count"],
        }
    if resource is not None:
        result["resource_anchors"] = resource
        result["interpretation"].append(
            "The ninth database revision also contains the separately reviewed resource matching, stream, and game-file resolution anchors."
        )
    script_bridge = None
    if args.script_bridge_anchors or args.script_bridge_verification:
        if not args.script_bridge_anchors or not args.script_bridge_verification:
            raise ValueError(
                "script-bridge anchors and script-bridge verification must be supplied together"
            )
        script_bridge_document = load(args.script_bridge_anchors)
        script_bridge_verification = load(args.script_bridge_verification)
        if script_bridge_document.get("artifact") != "spectron_script_bridge_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-bridge anchor artifact")
        if not script_bridge_verification.get("verified"):
            raise ValueError("script-bridge anchor reopen verification did not pass")
        expected_script_bridge = len(script_bridge_document["anchors"])
        if script_bridge_verification["verified_name_count"] != expected_script_bridge:
            raise ValueError("script-bridge verification count differs from artifact")
        script_bridge = {
            "anchor_path": str(args.script_bridge_anchors),
            "anchor_sha256": sha256_path(args.script_bridge_anchors),
            "reopen_verification": str(args.script_bridge_verification),
            "anchor_count": expected_script_bridge,
            "verified_name_count": script_bridge_verification["verified_name_count"],
            "reopen_failure_count": script_bridge_verification["failure_count"],
        }
    if script_bridge is not None:
        result["script_bridge_anchors"] = script_bridge
        result["interpretation"].append(
            "The tenth database revision also contains the separately reviewed client script bridge anchors."
        )
    client_request = None
    if args.client_request_anchors or args.client_request_verification:
        if not args.client_request_anchors or not args.client_request_verification:
            raise ValueError(
                "client-request anchors and client-request verification must be supplied together"
            )
        client_request_document = load(args.client_request_anchors)
        client_request_verification = load(args.client_request_verification)
        if client_request_document.get("artifact") != "spectron_client_request_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-request anchor artifact")
        if not client_request_verification.get("verified"):
            raise ValueError("client-request anchor reopen verification did not pass")
        expected_client_request = len(client_request_document["anchors"])
        if client_request_verification["verified_name_count"] != expected_client_request:
            raise ValueError("client-request verification count differs from artifact")
        client_request = {
            "anchor_path": str(args.client_request_anchors),
            "anchor_sha256": sha256_path(args.client_request_anchors),
            "reopen_verification": str(args.client_request_verification),
            "anchor_count": expected_client_request,
            "verified_name_count": client_request_verification["verified_name_count"],
            "reopen_failure_count": client_request_verification["failure_count"],
        }
    if client_request is not None:
        result["client_request_anchors"] = client_request
        result["interpretation"].append(
            "The eleventh database revision also contains the separately reviewed client request and window-state serializer anchors."
        )
    client_inbound = None
    if args.client_inbound_anchors or args.client_inbound_verification:
        if not args.client_inbound_anchors or not args.client_inbound_verification:
            raise ValueError(
                "client-inbound anchors and client-inbound verification must be supplied together"
            )
        client_inbound_document = load(args.client_inbound_anchors)
        client_inbound_verification = load(args.client_inbound_verification)
        if client_inbound_document.get("artifact") != "spectron_client_inbound_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-inbound anchor artifact")
        if not client_inbound_verification.get("verified"):
            raise ValueError("client-inbound anchor reopen verification did not pass")
        expected_client_inbound = len(client_inbound_document["anchors"])
        if client_inbound_verification["verified_name_count"] != expected_client_inbound:
            raise ValueError("client-inbound verification count differs from artifact")
        client_inbound = {
            "anchor_path": str(args.client_inbound_anchors),
            "anchor_sha256": sha256_path(args.client_inbound_anchors),
            "reopen_verification": str(args.client_inbound_verification),
            "anchor_count": expected_client_inbound,
            "verified_name_count": client_inbound_verification["verified_name_count"],
            "reopen_failure_count": client_inbound_verification["failure_count"],
        }
    if client_inbound is not None:
        result["client_inbound_anchors"] = client_inbound
        result["interpretation"].append(
            "The twelfth database revision also contains the separately reviewed client inbound and state-transition anchors."
        )
    login_helper = None
    if args.login_helper_anchors or args.login_helper_verification:
        if not args.login_helper_anchors or not args.login_helper_verification:
            raise ValueError(
                "login-helper anchors and login-helper verification must be supplied together"
            )
        login_helper_document = load(args.login_helper_anchors)
        login_helper_verification = load(args.login_helper_verification)
        if login_helper_document.get("artifact") != "spectron_login_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected login-helper anchor artifact")
        if not login_helper_verification.get("verified"):
            raise ValueError("login-helper anchor reopen verification did not pass")
        expected_login_helper = len(login_helper_document["anchors"])
        if login_helper_verification["verified_name_count"] != expected_login_helper:
            raise ValueError("login-helper verification count differs from artifact")
        login_helper = {
            "anchor_path": str(args.login_helper_anchors),
            "anchor_sha256": sha256_path(args.login_helper_anchors),
            "reopen_verification": str(args.login_helper_verification),
            "anchor_count": expected_login_helper,
            "verified_name_count": login_helper_verification["verified_name_count"],
            "reopen_failure_count": login_helper_verification["failure_count"],
        }
    if login_helper is not None:
        result["login_helper_anchors"] = login_helper
        result["interpretation"].append(
            "The thirteenth database revision also contains the separately reviewed login, event, and small client state helper anchors."
        )
    parse_wrapper = None
    if args.parse_wrapper_anchors or args.parse_wrapper_verification:
        if not args.parse_wrapper_anchors or not args.parse_wrapper_verification:
            raise ValueError(
                "parse-wrapper anchors and parse-wrapper verification must be supplied together"
            )
        parse_wrapper_document = load(args.parse_wrapper_anchors)
        parse_wrapper_verification = load(args.parse_wrapper_verification)
        if parse_wrapper_document.get("artifact") != "spectron_parse_wrapper_manual_translation_anchor_20260826":
            raise ValueError("unexpected parse-wrapper anchor artifact")
        if not parse_wrapper_verification.get("verified"):
            raise ValueError("parse-wrapper anchor reopen verification did not pass")
        expected_parse_wrapper = len(parse_wrapper_document["anchors"])
        if parse_wrapper_verification["verified_name_count"] != expected_parse_wrapper:
            raise ValueError("parse-wrapper verification count differs from artifact")
        parse_wrapper = {
            "anchor_path": str(args.parse_wrapper_anchors),
            "anchor_sha256": sha256_path(args.parse_wrapper_anchors),
            "reopen_verification": str(args.parse_wrapper_verification),
            "anchor_count": expected_parse_wrapper,
            "verified_name_count": parse_wrapper_verification["verified_name_count"],
            "reopen_failure_count": parse_wrapper_verification["failure_count"],
        }
    if parse_wrapper is not None:
        result["parse_wrapper_anchors"] = parse_wrapper
        result["interpretation"].append(
            "The fourteenth database revision also contains the separately reviewed client encryption-in tail-thunk anchor."
        )
    lookup_helper = None
    if args.lookup_helper_anchors or args.lookup_helper_verification:
        if not args.lookup_helper_anchors or not args.lookup_helper_verification:
            raise ValueError(
                "lookup-helper anchors and lookup-helper verification must be supplied together"
            )
        lookup_helper_document = load(args.lookup_helper_anchors)
        lookup_helper_verification = load(args.lookup_helper_verification)
        if lookup_helper_document.get("artifact") != "spectron_lookup_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected lookup-helper anchor artifact")
        if not lookup_helper_verification.get("verified"):
            raise ValueError("lookup-helper anchor reopen verification did not pass")
        expected_lookup_helper = len(lookup_helper_document["anchors"])
        if lookup_helper_verification["verified_name_count"] != expected_lookup_helper:
            raise ValueError("lookup-helper verification count differs from artifact")
        lookup_helper = {
            "anchor_path": str(args.lookup_helper_anchors),
            "anchor_sha256": sha256_path(args.lookup_helper_anchors),
            "reopen_verification": str(args.lookup_helper_verification),
            "anchor_count": expected_lookup_helper,
            "verified_name_count": lookup_helper_verification["verified_name_count"],
            "reopen_failure_count": lookup_helper_verification["failure_count"],
        }
    if lookup_helper is not None:
        result["lookup_helper_anchors"] = lookup_helper
        result["interpretation"].append(
            "The fifteenth database revision also contains the separately reviewed player and download lookup helper anchors."
        )
    connection_helper = None
    if args.connection_helper_anchors or args.connection_helper_verification:
        if not args.connection_helper_anchors or not args.connection_helper_verification:
            raise ValueError(
                "connection-helper anchors and connection-helper verification must be supplied together"
            )
        connection_helper_document = load(args.connection_helper_anchors)
        connection_helper_verification = load(args.connection_helper_verification)
        if connection_helper_document.get("artifact") != "spectron_connection_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected connection-helper anchor artifact")
        if not connection_helper_verification.get("verified"):
            raise ValueError("connection-helper anchor reopen verification did not pass")
        expected_connection_helper = len(connection_helper_document["anchors"])
        if connection_helper_verification["verified_name_count"] != expected_connection_helper:
            raise ValueError("connection-helper verification count differs from artifact")
        connection_helper = {
            "anchor_path": str(args.connection_helper_anchors),
            "anchor_sha256": sha256_path(args.connection_helper_anchors),
            "reopen_verification": str(args.connection_helper_verification),
            "anchor_count": expected_connection_helper,
            "verified_name_count": connection_helper_verification["verified_name_count"],
            "reopen_failure_count": connection_helper_verification["failure_count"],
        }
    if connection_helper is not None:
        result["connection_helper_anchors"] = connection_helper
        result["interpretation"].append(
            "The sixteenth database revision also contains the separately reviewed connection, packet-state, SSL, and low-level field anchors."
        )
    client_state_helper = None
    if args.client_state_helper_anchors or args.client_state_helper_verification:
        if not args.client_state_helper_anchors or not args.client_state_helper_verification:
            raise ValueError(
                "client-state-helper anchors and client-state-helper verification must be supplied together"
            )
        client_state_helper_document = load(args.client_state_helper_anchors)
        client_state_helper_verification = load(args.client_state_helper_verification)
        if client_state_helper_document.get("artifact") != "spectron_client_state_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-state-helper anchor artifact")
        if not client_state_helper_verification.get("verified"):
            raise ValueError("client-state-helper anchor reopen verification did not pass")
        expected_client_state_helper = len(client_state_helper_document["anchors"])
        if client_state_helper_verification["verified_name_count"] != expected_client_state_helper:
            raise ValueError("client-state-helper verification count differs from artifact")
        client_state_helper = {
            "anchor_path": str(args.client_state_helper_anchors),
            "anchor_sha256": sha256_path(args.client_state_helper_anchors),
            "reopen_verification": str(args.client_state_helper_verification),
            "anchor_count": expected_client_state_helper,
            "verified_name_count": client_state_helper_verification["verified_name_count"],
            "reopen_failure_count": client_state_helper_verification["failure_count"],
        }
    if client_state_helper is not None:
        result["client_state_helper_anchors"] = client_state_helper
        result["interpretation"].append(
            "The seventeenth database revision also contains the separately reviewed compact client state and forwarding anchors."
        )
    connection_state = None
    if args.connection_state_anchors or args.connection_state_verification:
        if not args.connection_state_anchors or not args.connection_state_verification:
            raise ValueError(
                "connection-state anchors and connection-state verification must be supplied together"
            )
        connection_state_document = load(args.connection_state_anchors)
        connection_state_verification = load(args.connection_state_verification)
        if connection_state_document.get("artifact") != "spectron_connection_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected connection-state anchor artifact")
        if not connection_state_verification.get("verified"):
            raise ValueError("connection-state anchor reopen verification did not pass")
        expected_connection_state = len(connection_state_document["anchors"])
        if connection_state_verification["verified_name_count"] != expected_connection_state:
            raise ValueError("connection-state verification count differs from artifact")
        connection_state = {
            "anchor_path": str(args.connection_state_anchors),
            "anchor_sha256": sha256_path(args.connection_state_anchors),
            "reopen_verification": str(args.connection_state_verification),
            "anchor_count": expected_connection_state,
            "verified_name_count": connection_state_verification["verified_name_count"],
            "reopen_failure_count": connection_state_verification["failure_count"],
        }
    if connection_state is not None:
        result["connection_state_anchors"] = connection_state
        result["interpretation"].append(
            "The eighteenth database revision also contains the separately reviewed client connection-state and encrypted-file helper anchors."
        )
    http_request = None
    if args.http_request_anchors or args.http_request_verification:
        if not args.http_request_anchors or not args.http_request_verification:
            raise ValueError(
                "HTTP request anchors and HTTP request verification must be supplied together"
            )
        http_request_document = load(args.http_request_anchors)
        http_request_verification = load(args.http_request_verification)
        if http_request_document.get("artifact") != "spectron_http_request_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTTP request anchor artifact")
        if not http_request_verification.get("verified"):
            raise ValueError("HTTP request anchor reopen verification did not pass")
        expected_http_request = len(http_request_document["anchors"])
        if http_request_verification["verified_name_count"] != expected_http_request:
            raise ValueError("HTTP request verification count differs from artifact")
        http_request = {
            "anchor_path": str(args.http_request_anchors),
            "anchor_sha256": sha256_path(args.http_request_anchors),
            "reopen_verification": str(args.http_request_verification),
            "anchor_count": expected_http_request,
            "verified_name_count": http_request_verification["verified_name_count"],
            "reopen_failure_count": http_request_verification["failure_count"],
        }
    if http_request is not None:
        result["http_request_anchors"] = http_request
        result["interpretation"].append(
            "The nineteenth database revision also contains the separately reviewed HTTP request field, lifecycle, and outbound-buffer anchors."
        )
    socket_state = None
    if args.socket_state_anchors or args.socket_state_verification:
        if not args.socket_state_anchors or not args.socket_state_verification:
            raise ValueError(
                "socket-state anchors and socket-state verification must be supplied together"
            )
        socket_state_document = load(args.socket_state_anchors)
        socket_state_verification = load(args.socket_state_verification)
        if socket_state_document.get("artifact") != "spectron_socket_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected socket-state anchor artifact")
        if not socket_state_verification.get("verified"):
            raise ValueError("socket-state anchor reopen verification did not pass")
        expected_socket_state = len(socket_state_document["anchors"])
        if socket_state_verification["verified_name_count"] != expected_socket_state:
            raise ValueError("socket-state verification count differs from artifact")
        socket_state = {
            "anchor_path": str(args.socket_state_anchors),
            "anchor_sha256": sha256_path(args.socket_state_anchors),
            "reopen_verification": str(args.socket_state_verification),
            "anchor_count": expected_socket_state,
            "verified_name_count": socket_state_verification["verified_name_count"],
            "reopen_failure_count": socket_state_verification["failure_count"],
        }
    if socket_state is not None:
        result["socket_state_anchors"] = socket_state
        result["interpretation"].append(
            "The twentieth database revision also contains the separately reviewed socket status and address helper anchors."
        )
    http_request_state = None
    if args.http_request_state_anchors or args.http_request_state_verification:
        if not args.http_request_state_anchors or not args.http_request_state_verification:
            raise ValueError(
                "HTTP request-state anchors and HTTP request-state verification must be supplied together"
            )
        http_request_state_document = load(args.http_request_state_anchors)
        http_request_state_verification = load(args.http_request_state_verification)
        if http_request_state_document.get("artifact") != "spectron_http_request_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTTP request-state anchor artifact")
        if not http_request_state_verification.get("verified"):
            raise ValueError("HTTP request-state anchor reopen verification did not pass")
        expected_http_request_state = len(http_request_state_document["anchors"])
        if http_request_state_verification["verified_name_count"] != expected_http_request_state:
            raise ValueError("HTTP request-state verification count differs from artifact")
        http_request_state = {
            "anchor_path": str(args.http_request_state_anchors),
            "anchor_sha256": sha256_path(args.http_request_state_anchors),
            "reopen_verification": str(args.http_request_state_verification),
            "anchor_count": expected_http_request_state,
            "verified_name_count": http_request_state_verification["verified_name_count"],
            "reopen_failure_count": http_request_state_verification["failure_count"],
        }
    if http_request_state is not None:
        result["http_request_state_anchors"] = http_request_state
        result["interpretation"].append(
            "The twenty-first database revision also contains the separately reviewed HTTP request counters and download-state anchors."
        )
    npc_helper = None
    if args.npc_helper_anchors or args.npc_helper_verification:
        if not args.npc_helper_anchors or not args.npc_helper_verification:
            raise ValueError(
                "NPC helper anchors and NPC helper verification must be supplied together"
            )
        npc_helper_document = load(args.npc_helper_anchors)
        npc_helper_verification = load(args.npc_helper_verification)
        if npc_helper_document.get("artifact") != "spectron_npc_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected NPC helper anchor artifact")
        if not npc_helper_verification.get("verified"):
            raise ValueError("NPC helper anchor reopen verification did not pass")
        expected_npc_helper = len(npc_helper_document["anchors"])
        if npc_helper_verification["verified_name_count"] != expected_npc_helper:
            raise ValueError("NPC helper verification count differs from artifact")
        npc_helper = {
            "anchor_path": str(args.npc_helper_anchors),
            "anchor_sha256": sha256_path(args.npc_helper_anchors),
            "reopen_verification": str(args.npc_helper_verification),
            "anchor_count": expected_npc_helper,
            "verified_name_count": npc_helper_verification["verified_name_count"],
            "reopen_failure_count": npc_helper_verification["failure_count"],
        }
    if npc_helper is not None:
        result["npc_helper_anchors"] = npc_helper
        result["interpretation"].append(
            "The twenty-second database revision also contains the separately reviewed TServerNPC blocking, draw-mode, visibility, bow, and pelt helper anchors."
        )
    html_atom = None
    if args.html_atom_anchors or args.html_atom_verification:
        if not args.html_atom_anchors or not args.html_atom_verification:
            raise ValueError(
                "HTML atom anchors and HTML atom verification must be supplied together"
            )
        html_atom_document = load(args.html_atom_anchors)
        html_atom_verification = load(args.html_atom_verification)
        if html_atom_document.get("artifact") != "spectron_html_atom_manual_translation_anchors_20260826":
            raise ValueError("unexpected HTML atom anchor artifact")
        if not html_atom_verification.get("verified"):
            raise ValueError("HTML atom anchor reopen verification did not pass")
        expected_html_atom = len(html_atom_document["anchors"])
        if html_atom_verification["verified_name_count"] != expected_html_atom:
            raise ValueError("HTML atom verification count differs from artifact")
        html_atom = {
            "anchor_path": str(args.html_atom_anchors),
            "anchor_sha256": sha256_path(args.html_atom_anchors),
            "reopen_verification": str(args.html_atom_verification),
            "anchor_count": expected_html_atom,
            "verified_name_count": html_atom_verification["verified_name_count"],
            "reopen_failure_count": html_atom_verification["failure_count"],
        }
    if html_atom is not None:
        result["html_atom_anchors"] = html_atom
        result["interpretation"].append(
            "The twenty-third database revision also contains the separately reviewed THTMLAtom constructor and buffer accessor anchors."
        )
    player_helper = None
    if args.player_helper_anchors or args.player_helper_verification:
        if not args.player_helper_anchors or not args.player_helper_verification:
            raise ValueError(
                "player helper anchors and player helper verification must be supplied together"
            )
        player_helper_document = load(args.player_helper_anchors)
        player_helper_verification = load(args.player_helper_verification)
        if player_helper_document.get("artifact") != "spectron_player_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected player helper anchor artifact")
        if not player_helper_verification.get("verified"):
            raise ValueError("player helper anchor reopen verification did not pass")
        expected_player_helper = len(player_helper_document["anchors"])
        if player_helper_verification["verified_name_count"] != expected_player_helper:
            raise ValueError("player helper verification count differs from artifact")
        player_helper = {
            "anchor_path": str(args.player_helper_anchors),
            "anchor_sha256": sha256_path(args.player_helper_anchors),
            "reopen_verification": str(args.player_helper_verification),
            "anchor_count": expected_player_helper,
            "verified_name_count": player_helper_verification["verified_name_count"],
            "reopen_failure_count": player_helper_verification["failure_count"],
        }
    if player_helper is not None:
        result["player_helper_anchors"] = player_helper
        result["interpretation"].append(
            "The twenty-fourth database revision also contains the separately reviewed compact TPlayer attachment, update, freeze, and sprite helper anchors."
        )
    input_window = None
    if args.input_window_anchors or args.input_window_verification:
        if not args.input_window_anchors or not args.input_window_verification:
            raise ValueError(
                "input/window anchors and input/window verification must be supplied together"
            )
        input_window_document = load(args.input_window_anchors)
        input_window_verification = load(args.input_window_verification)
        if input_window_document.get("artifact") != "spectron_input_window_manual_translation_anchors_20260826":
            raise ValueError("unexpected input/window anchor artifact")
        if not input_window_verification.get("verified"):
            raise ValueError("input/window anchor reopen verification did not pass")
        expected_input_window = len(input_window_document["anchors"])
        if input_window_verification["verified_name_count"] != expected_input_window:
            raise ValueError("input/window verification count differs from artifact")
        input_window = {
            "anchor_path": str(args.input_window_anchors),
            "anchor_sha256": sha256_path(args.input_window_anchors),
            "reopen_verification": str(args.input_window_verification),
            "anchor_count": expected_input_window,
            "verified_name_count": input_window_verification["verified_name_count"],
            "reopen_failure_count": input_window_verification["failure_count"],
        }
    if input_window is not None:
        result["input_window_anchors"] = input_window
        result["interpretation"].append(
            "The twenty-fifth database revision also contains the separately reviewed input and window bridge helper anchors."
        )
    visual_helper = None
    if args.visual_helper_anchors or args.visual_helper_verification:
        if not args.visual_helper_anchors or not args.visual_helper_verification:
            raise ValueError(
                "visual helper anchors and visual helper verification must be supplied together"
            )
        visual_helper_document = load(args.visual_helper_anchors)
        visual_helper_verification = load(args.visual_helper_verification)
        if visual_helper_document.get("artifact") != "spectron_visual_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected visual helper anchor artifact")
        if not visual_helper_verification.get("verified"):
            raise ValueError("visual helper anchor reopen verification did not pass")
        expected_visual_helper = len(visual_helper_document["anchors"])
        if visual_helper_verification["verified_name_count"] != expected_visual_helper:
            raise ValueError("visual helper verification count differs from artifact")
        visual_helper = {
            "anchor_path": str(args.visual_helper_anchors),
            "anchor_sha256": sha256_path(args.visual_helper_anchors),
            "reopen_verification": str(args.visual_helper_verification),
            "anchor_count": expected_visual_helper,
            "verified_name_count": visual_helper_verification["verified_name_count"],
            "reopen_failure_count": visual_helper_verification["failure_count"],
        }
    if visual_helper is not None:
        result["visual_helper_anchors"] = visual_helper
        result["interpretation"].append(
            "The twenty-sixth database revision also contains the separately reviewed animation, particle, and show-image helper anchors."
        )
    script_runtime = None
    if args.script_runtime_anchors or args.script_runtime_verification:
        if not args.script_runtime_anchors or not args.script_runtime_verification:
            raise ValueError(
                "script-runtime anchors and script-runtime verification must be supplied together"
            )
        script_runtime_document = load(args.script_runtime_anchors)
        script_runtime_verification = load(args.script_runtime_verification)
        if script_runtime_document.get("artifact") != "spectron_script_runtime_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-runtime anchor artifact")
        if not script_runtime_verification.get("verified"):
            raise ValueError("script-runtime anchor reopen verification did not pass")
        expected_script_runtime = len(script_runtime_document["anchors"])
        if script_runtime_verification["verified_name_count"] != expected_script_runtime:
            raise ValueError("script-runtime verification count differs from artifact")
        script_runtime = {
            "anchor_path": str(args.script_runtime_anchors),
            "anchor_sha256": sha256_path(args.script_runtime_anchors),
            "reopen_verification": str(args.script_runtime_verification),
            "anchor_count": expected_script_runtime,
            "verified_name_count": script_runtime_verification["verified_name_count"],
            "reopen_failure_count": script_runtime_verification["failure_count"],
        }
    if script_runtime is not None:
        result["script_runtime_anchors"] = script_runtime
        result["interpretation"].append(
            "The twenty-seventh database revision also contains the separately reviewed GS2-facing TGraalVar, TScript, TScriptSpace, and TScriptUniverse helper anchors."
        )
    core_helper = None
    if args.core_helper_anchors or args.core_helper_verification:
        if not args.core_helper_anchors or not args.core_helper_verification:
            raise ValueError(
                "core-helper anchors and core-helper verification must be supplied together"
            )
        core_helper_document = load(args.core_helper_anchors)
        core_helper_verification = load(args.core_helper_verification)
        if core_helper_document.get("artifact") != "spectron_core_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected core-helper anchor artifact")
        if not core_helper_verification.get("verified"):
            raise ValueError("core-helper anchor reopen verification did not pass")
        expected_core_helper = len(core_helper_document["anchors"])
        if core_helper_verification["verified_name_count"] != expected_core_helper:
            raise ValueError("core-helper verification count differs from artifact")
        core_helper = {
            "anchor_path": str(args.core_helper_anchors),
            "anchor_sha256": sha256_path(args.core_helper_anchors),
            "reopen_verification": str(args.core_helper_verification),
            "anchor_count": expected_core_helper,
            "verified_name_count": core_helper_verification["verified_name_count"],
            "reopen_failure_count": core_helper_verification["failure_count"],
        }
    if core_helper is not None:
        result["core_helper_anchors"] = core_helper
        result["interpretation"].append(
            "The twenty-eighth database revision also contains the separately reviewed level, script, network-policy, tile, particle, and native callback helper anchors."
        )
    render_gui = None
    if args.render_gui_anchors or args.render_gui_verification:
        if not args.render_gui_anchors or not args.render_gui_verification:
            raise ValueError(
                "render/GUI anchors and render/GUI verification must be supplied together"
            )
        render_gui_document = load(args.render_gui_anchors)
        render_gui_verification = load(args.render_gui_verification)
        if render_gui_document.get("artifact") != "spectron_render_gui_manual_translation_anchors_20260826":
            raise ValueError("unexpected render/GUI anchor artifact")
        if not render_gui_verification.get("verified"):
            raise ValueError("render/GUI anchor reopen verification did not pass")
        expected_render_gui = len(render_gui_document["anchors"])
        if render_gui_verification["verified_name_count"] != expected_render_gui:
            raise ValueError("render/GUI verification count differs from artifact")
        render_gui = {
            "anchor_path": str(args.render_gui_anchors),
            "anchor_sha256": sha256_path(args.render_gui_anchors),
            "reopen_verification": str(args.render_gui_verification),
            "anchor_count": expected_render_gui,
            "verified_name_count": render_gui_verification["verified_name_count"],
            "reopen_failure_count": render_gui_verification["failure_count"],
        }
    if render_gui is not None:
        result["render_gui_anchors"] = render_gui
        result["interpretation"].append(
            "The twenty-ninth database revision also contains the separately reviewed texture, OpenGL, drawing-panel, GUI-control, markup, and scrolling helper anchors."
        )
    json_folder = None
    if args.json_folder_anchors or args.json_folder_verification:
        if not args.json_folder_anchors or not args.json_folder_verification:
            raise ValueError(
                "JSON/folder anchors and JSON/folder verification must be supplied together"
            )
        json_folder_document = load(args.json_folder_anchors)
        json_folder_verification = load(args.json_folder_verification)
        if json_folder_document.get("artifact") != "spectron_json_folder_manual_translation_anchors_20260826":
            raise ValueError("unexpected JSON/folder anchor artifact")
        if not json_folder_verification.get("verified"):
            raise ValueError("JSON/folder anchor reopen verification did not pass")
        expected_json_folder = len(json_folder_document["anchors"])
        if json_folder_verification["verified_name_count"] != expected_json_folder:
            raise ValueError("JSON/folder verification count differs from artifact")
        json_folder = {
            "anchor_path": str(args.json_folder_anchors),
            "anchor_sha256": sha256_path(args.json_folder_anchors),
            "reopen_verification": str(args.json_folder_verification),
            "anchor_count": expected_json_folder,
            "verified_name_count": json_folder_verification["verified_name_count"],
            "reopen_failure_count": json_folder_verification["failure_count"],
        }
    if json_folder is not None:
        result["json_folder_anchors"] = json_folder
        result["interpretation"].append(
            "The thirtieth database revision also contains the separately reviewed image callbacks, recursive folder-loader helper, and YAJL JSON callback anchors."
        )
    resource_object = None
    if args.resource_object_anchors or args.resource_object_verification:
        if not args.resource_object_anchors or not args.resource_object_verification:
            raise ValueError(
                "resource-object anchors and resource-object verification must be supplied together"
            )
        resource_object_document = load(args.resource_object_anchors)
        resource_object_verification = load(args.resource_object_verification)
        if resource_object_document.get("artifact") != "spectron_resource_object_manual_translation_anchors_20260826":
            raise ValueError("unexpected resource-object anchor artifact")
        if not resource_object_verification.get("verified"):
            raise ValueError("resource-object anchor reopen verification did not pass")
        expected_resource_object = len(resource_object_document["anchors"])
        if resource_object_verification["verified_name_count"] != expected_resource_object:
            raise ValueError("resource-object verification count differs from artifact")
        resource_object = {
            "anchor_path": str(args.resource_object_anchors),
            "anchor_sha256": sha256_path(args.resource_object_anchors),
            "reopen_verification": str(args.resource_object_verification),
            "anchor_count": expected_resource_object,
            "verified_name_count": resource_object_verification["verified_name_count"],
            "reopen_failure_count": resource_object_verification["failure_count"],
        }
    if resource_object is not None:
        result["resource_object_anchors"] = resource_object
        result["interpretation"].append(
            "The thirty-first database revision also contains the separately reviewed resource comparator, link, alternative, and stream-materialization anchors."
        )
    script_machine = None
    if args.script_machine_anchors or args.script_machine_verification:
        if not args.script_machine_anchors or not args.script_machine_verification:
            raise ValueError(
                "script-machine anchors and script-machine verification must be supplied together"
            )
        script_machine_document = load(args.script_machine_anchors)
        script_machine_verification = load(args.script_machine_verification)
        if script_machine_document.get("artifact") != "spectron_script_machine_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-machine anchor artifact")
        if not script_machine_verification.get("verified"):
            raise ValueError("script-machine anchor reopen verification did not pass")
        expected_script_machine = len(script_machine_document["anchors"])
        if script_machine_verification["verified_name_count"] != expected_script_machine:
            raise ValueError("script-machine verification count differs from artifact")
        script_machine = {
            "anchor_path": str(args.script_machine_anchors),
            "anchor_sha256": sha256_path(args.script_machine_anchors),
            "reopen_verification": str(args.script_machine_verification),
            "anchor_count": expected_script_machine,
            "verified_name_count": script_machine_verification["verified_name_count"],
            "reopen_failure_count": script_machine_verification["failure_count"],
        }
    if script_machine is not None:
        result["script_machine_anchors"] = script_machine
        result["interpretation"].append(
            "The thirty-second database revision also contains the separately reviewed GS2 script-machine construction, resolution, assignment, and comparison anchors."
        )
    script_space = None
    if args.script_space_anchors or args.script_space_verification:
        if not args.script_space_anchors or not args.script_space_verification:
            raise ValueError(
                "script-space anchors and script-space verification must be supplied together"
            )
        script_space_document = load(args.script_space_anchors)
        script_space_verification = load(args.script_space_verification)
        if script_space_document.get("artifact") != "spectron_script_space_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-space anchor artifact")
        if not script_space_verification.get("verified"):
            raise ValueError("script-space anchor reopen verification did not pass")
        expected_script_space = len(script_space_document["anchors"])
        if script_space_verification["verified_name_count"] != expected_script_space:
            raise ValueError("script-space verification count differs from artifact")
        script_space = {
            "anchor_path": str(args.script_space_anchors),
            "anchor_sha256": sha256_path(args.script_space_anchors),
            "reopen_verification": str(args.script_space_verification),
            "anchor_count": expected_script_space,
            "verified_name_count": script_space_verification["verified_name_count"],
            "reopen_failure_count": script_space_verification["failure_count"],
        }
    if script_space is not None:
        result["script_space_anchors"] = script_space
        result["interpretation"].append(
            "The thirty-third database revision also contains the separately reviewed TScriptSpace event, class-transition, event-state, and timeout anchors."
        )
    script_execution = None
    if args.script_execution_anchors or args.script_execution_verification:
        if not args.script_execution_anchors or not args.script_execution_verification:
            raise ValueError(
                "script-execution anchors and script-execution verification must be supplied together"
            )
        script_execution_document = load(args.script_execution_anchors)
        script_execution_verification = load(args.script_execution_verification)
        if script_execution_document.get("artifact") != "spectron_script_execution_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-execution anchor artifact")
        if not script_execution_verification.get("verified"):
            raise ValueError("script-execution anchor reopen verification did not pass")
        expected_script_execution = len(script_execution_document["anchors"])
        if script_execution_verification["verified_name_count"] != expected_script_execution:
            raise ValueError("script-execution verification count differs from artifact")
        script_execution = {
            "anchor_path": str(args.script_execution_anchors),
            "anchor_sha256": sha256_path(args.script_execution_anchors),
            "reopen_verification": str(args.script_execution_verification),
            "anchor_count": expected_script_execution,
            "verified_name_count": script_execution_verification["verified_name_count"],
            "reopen_failure_count": script_execution_verification["failure_count"],
        }
    if script_execution is not None:
        result["script_execution_anchors"] = script_execution
        result["interpretation"].append(
            "The thirty-fourth database revision also contains the separately reviewed GS2 function-invocation, action-dispatch, caller-wake-up, and action-cleanup anchors."
        )
    script_dispatch = None
    if args.script_dispatch_anchors or args.script_dispatch_verification:
        if not args.script_dispatch_anchors or not args.script_dispatch_verification:
            raise ValueError(
                "script-dispatch anchors and script-dispatch verification must be supplied together"
            )
        script_dispatch_document = load(args.script_dispatch_anchors)
        script_dispatch_verification = load(args.script_dispatch_verification)
        if script_dispatch_document.get("artifact") != "spectron_script_dispatch_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-dispatch anchor artifact")
        if not script_dispatch_verification.get("verified"):
            raise ValueError("script-dispatch anchor reopen verification did not pass")
        expected_script_dispatch = len(script_dispatch_document["anchors"])
        if script_dispatch_verification["verified_name_count"] != expected_script_dispatch:
            raise ValueError("script-dispatch verification count differs from artifact")
        script_dispatch = {
            "anchor_path": str(args.script_dispatch_anchors),
            "anchor_sha256": sha256_path(args.script_dispatch_anchors),
            "reopen_verification": str(args.script_dispatch_verification),
            "anchor_count": expected_script_dispatch,
            "verified_name_count": script_dispatch_verification["verified_name_count"],
            "reopen_failure_count": script_dispatch_verification["failure_count"],
        }
    if script_dispatch is not None:
        result["script_dispatch_anchors"] = script_dispatch
        result["interpretation"].append(
            "The thirty-fifth database revision also contains the separately reviewed GS2 script-state, top-level action, and incoming-event dispatch anchors."
        )
    script_scheduler = None
    if args.script_scheduler_anchors or args.script_scheduler_verification:
        if not args.script_scheduler_anchors or not args.script_scheduler_verification:
            raise ValueError(
                "script-scheduler anchors and script-scheduler verification must be supplied together"
            )
        script_scheduler_document = load(args.script_scheduler_anchors)
        script_scheduler_verification = load(args.script_scheduler_verification)
        if script_scheduler_document.get("artifact") != "spectron_script_scheduler_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-scheduler anchor artifact")
        if not script_scheduler_verification.get("verified"):
            raise ValueError("script-scheduler anchor reopen verification did not pass")
        expected_script_scheduler = len(script_scheduler_document["anchors"])
        if script_scheduler_verification["verified_name_count"] != expected_script_scheduler:
            raise ValueError("script-scheduler verification count differs from artifact")
        script_scheduler = {
            "anchor_path": str(args.script_scheduler_anchors),
            "anchor_sha256": sha256_path(args.script_scheduler_anchors),
            "reopen_verification": str(args.script_scheduler_verification),
            "anchor_count": expected_script_scheduler,
            "verified_name_count": script_scheduler_verification["verified_name_count"],
            "reopen_failure_count": script_scheduler_verification["failure_count"],
        }
    if script_scheduler is not None:
        result["script_scheduler_anchors"] = script_scheduler
        result["interpretation"].append(
            "The thirty-sixth database revision also contains the separately reviewed GS2 scheduler, action-loop, event-object cleanup, and class-list replacement anchors."
        )
    event_object = None
    if args.event_object_anchors or args.event_object_verification:
        if not args.event_object_anchors or not args.event_object_verification:
            raise ValueError(
                "event-object anchors and event-object verification must be supplied together"
            )
        event_object_document = load(args.event_object_anchors)
        event_object_verification = load(args.event_object_verification)
        if event_object_document.get("artifact") != "spectron_event_object_manual_translation_anchors_20260826":
            raise ValueError("unexpected event-object anchor artifact")
        if not event_object_verification.get("verified"):
            raise ValueError("event-object anchor reopen verification did not pass")
        expected_event_object = len(event_object_document["anchors"])
        if event_object_verification["verified_name_count"] != expected_event_object:
            raise ValueError("event-object verification count differs from artifact")
        event_object = {
            "anchor_path": str(args.event_object_anchors),
            "anchor_sha256": sha256_path(args.event_object_anchors),
            "reopen_verification": str(args.event_object_verification),
            "anchor_count": expected_event_object,
            "verified_name_count": event_object_verification["verified_name_count"],
            "reopen_failure_count": event_object_verification["failure_count"],
        }
    if event_object is not None:
        result["event_object_anchors"] = event_object
        result["interpretation"].append(
            "The thirty-seventh database revision also contains the separately reviewed event-object and catcher-list constructor, destructor, registration, and receive-path anchors."
        )
    script_action = None
    if args.script_action_anchors or args.script_action_verification:
        if not args.script_action_anchors or not args.script_action_verification:
            raise ValueError(
                "script-action anchors and script-action verification must be supplied together"
            )
        script_action_document = load(args.script_action_anchors)
        script_action_verification = load(args.script_action_verification)
        if script_action_document.get("artifact") != "spectron_script_action_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-action anchor artifact")
        if not script_action_verification.get("verified"):
            raise ValueError("script-action anchor reopen verification did not pass")
        expected_script_action = len(script_action_document["anchors"])
        if script_action_verification["verified_name_count"] != expected_script_action:
            raise ValueError("script-action verification count differs from artifact")
        script_action = {
            "anchor_path": str(args.script_action_anchors),
            "anchor_sha256": sha256_path(args.script_action_anchors),
            "reopen_verification": str(args.script_action_verification),
            "anchor_count": expected_script_action,
            "verified_name_count": script_action_verification["verified_name_count"],
            "reopen_failure_count": script_action_verification["failure_count"],
        }
    if script_action is not None:
        result["script_action_anchors"] = script_action
        result["interpretation"].append(
            "The thirty-eighth database revision also contains the separately reviewed GS2 script-action constructor and destructor anchors."
        )
    stack_entry = None
    if args.stack_entry_anchors or args.stack_entry_verification:
        if not args.stack_entry_anchors or not args.stack_entry_verification:
            raise ValueError(
                "stack-entry anchors and stack-entry verification must be supplied together"
            )
        stack_entry_document = load(args.stack_entry_anchors)
        stack_entry_verification = load(args.stack_entry_verification)
        if stack_entry_document.get("artifact") != "spectron_stack_entry_manual_translation_anchors_20260826":
            raise ValueError("unexpected stack-entry anchor artifact")
        if not stack_entry_verification.get("verified"):
            raise ValueError("stack-entry anchor reopen verification did not pass")
        expected_stack_entry = len(stack_entry_document["anchors"])
        if stack_entry_verification["verified_name_count"] != expected_stack_entry:
            raise ValueError("stack-entry verification count differs from artifact")
        stack_entry = {
            "anchor_path": str(args.stack_entry_anchors),
            "anchor_sha256": sha256_path(args.stack_entry_anchors),
            "reopen_verification": str(args.stack_entry_verification),
            "anchor_count": expected_stack_entry,
            "verified_name_count": stack_entry_verification["verified_name_count"],
            "reopen_failure_count": stack_entry_verification["failure_count"],
        }
    if stack_entry is not None:
        result["stack_entry_anchors"] = stack_entry
        result["interpretation"].append(
            "The thirty-ninth database revision also contains the separately reviewed GS2 stack-entry float, string, and object conversion anchors."
        )
    machine_helper = None
    if args.machine_helper_anchors or args.machine_helper_verification:
        if not args.machine_helper_anchors or not args.machine_helper_verification:
            raise ValueError(
                "machine-helper anchors and machine-helper verification must be supplied together"
            )
        machine_helper_document = load(args.machine_helper_anchors)
        machine_helper_verification = load(args.machine_helper_verification)
        if machine_helper_document.get("artifact") != "spectron_machine_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected machine-helper anchor artifact")
        if not machine_helper_verification.get("verified"):
            raise ValueError("machine-helper anchor reopen verification did not pass")
        expected_machine_helper = len(machine_helper_document["anchors"])
        if machine_helper_verification["verified_name_count"] != expected_machine_helper:
            raise ValueError("machine-helper verification count differs from artifact")
        machine_helper = {
            "anchor_path": str(args.machine_helper_anchors),
            "anchor_sha256": sha256_path(args.machine_helper_anchors),
            "reopen_verification": str(args.machine_helper_verification),
            "anchor_count": expected_machine_helper,
            "verified_name_count": machine_helper_verification["verified_name_count"],
            "reopen_failure_count": machine_helper_verification["failure_count"],
        }
    if machine_helper is not None:
        result["machine_helper_anchors"] = machine_helper
        result["interpretation"].append(
            "The fortieth database revision also contains the separately reviewed execution restoration, character extraction, and action-context lookup anchors."
        )
    array_mutation = None
    if args.array_mutation_anchors or args.array_mutation_verification:
        if not args.array_mutation_anchors or not args.array_mutation_verification:
            raise ValueError(
                "array-mutation anchors and array-mutation verification must be supplied together"
            )
        array_mutation_document = load(args.array_mutation_anchors)
        array_mutation_verification = load(args.array_mutation_verification)
        if array_mutation_document.get("artifact") != "spectron_array_mutation_manual_translation_anchors_20260826":
            raise ValueError("unexpected array-mutation anchor artifact")
        if not array_mutation_verification.get("verified"):
            raise ValueError("array-mutation anchor reopen verification did not pass")
        expected_array_mutation = len(array_mutation_document["anchors"])
        if array_mutation_verification["verified_name_count"] != expected_array_mutation:
            raise ValueError("array-mutation verification count differs from artifact")
        array_mutation = {
            "anchor_path": str(args.array_mutation_anchors),
            "anchor_sha256": sha256_path(args.array_mutation_anchors),
            "reopen_verification": str(args.array_mutation_verification),
            "anchor_count": expected_array_mutation,
            "verified_name_count": array_mutation_verification["verified_name_count"],
            "reopen_failure_count": array_mutation_verification["failure_count"],
        }
    if array_mutation is not None:
        result["array_mutation_anchors"] = array_mutation
        result["interpretation"].append(
            "The forty-first database revision also contains the separately reviewed GS2 single-cell, two-dimensional, and replacement array mutation anchors."
        )
    string_search = None
    if args.string_search_anchors or args.string_search_verification:
        if not args.string_search_anchors or not args.string_search_verification:
            raise ValueError(
                "string-search anchors and string-search verification must be supplied together"
            )
        string_search_document = load(args.string_search_anchors)
        string_search_verification = load(args.string_search_verification)
        if string_search_document.get("artifact") != "spectron_string_search_manual_translation_anchors_20260826":
            raise ValueError("unexpected string-search anchor artifact")
        if not string_search_verification.get("verified"):
            raise ValueError("string-search anchor reopen verification did not pass")
        expected_string_search = len(string_search_document["anchors"])
        if string_search_verification["verified_name_count"] != expected_string_search:
            raise ValueError("string-search verification count differs from artifact")
        string_search = {
            "anchor_path": str(args.string_search_anchors),
            "anchor_sha256": sha256_path(args.string_search_anchors),
            "reopen_verification": str(args.string_search_verification),
            "anchor_count": expected_string_search,
            "verified_name_count": string_search_verification["verified_name_count"],
            "reopen_failure_count": string_search_verification["failure_count"],
        }
    if string_search is not None:
        result["string_search_anchors"] = string_search
        result["interpretation"].append(
            "The forty-second database revision also contains the separately reviewed GS2 all-index and substring-position search anchors."
        )
    string_helper = None
    if args.string_helper_anchors or args.string_helper_verification:
        if not args.string_helper_anchors or not args.string_helper_verification:
            raise ValueError(
                "string-helper anchors and string-helper verification must be supplied together"
            )
        string_helper_document = load(args.string_helper_anchors)
        string_helper_verification = load(args.string_helper_verification)
        if string_helper_document.get("artifact") != "spectron_string_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected string-helper anchor artifact")
        if not string_helper_verification.get("verified"):
            raise ValueError("string-helper anchor reopen verification did not pass")
        expected_string_helper = len(string_helper_document["anchors"])
        if string_helper_verification["verified_name_count"] != expected_string_helper:
            raise ValueError("string-helper verification count differs from artifact")
        string_helper = {
            "anchor_path": str(args.string_helper_anchors),
            "anchor_sha256": sha256_path(args.string_helper_anchors),
            "reopen_verification": str(args.string_helper_verification),
            "anchor_count": expected_string_helper,
            "verified_name_count": string_helper_verification["verified_name_count"],
            "reopen_failure_count": string_helper_verification["failure_count"],
        }
    if string_helper is not None:
        result["string_helper_anchors"] = string_helper
        result["interpretation"].append(
            "The forty-third database revision also contains the separately reviewed GS2 next-string, indexed-string, and string-formatting helper anchors."
        )
    variable_construction = None
    if args.variable_construction_anchors or args.variable_construction_verification:
        if not args.variable_construction_anchors or not args.variable_construction_verification:
            raise ValueError(
                "variable-construction anchors and variable-construction verification must be supplied together"
            )
        variable_construction_document = load(args.variable_construction_anchors)
        variable_construction_verification = load(args.variable_construction_verification)
        if variable_construction_document.get("artifact") != "spectron_variable_construction_manual_translation_anchors_20260826":
            raise ValueError("unexpected variable-construction anchor artifact")
        if not variable_construction_verification.get("verified"):
            raise ValueError("variable-construction anchor reopen verification did not pass")
        expected_variable_construction = len(variable_construction_document["anchors"])
        if variable_construction_verification["verified_name_count"] != expected_variable_construction:
            raise ValueError("variable-construction verification count differs from artifact")
        variable_construction = {
            "anchor_path": str(args.variable_construction_anchors),
            "anchor_sha256": sha256_path(args.variable_construction_anchors),
            "reopen_verification": str(args.variable_construction_verification),
            "anchor_count": expected_variable_construction,
            "verified_name_count": variable_construction_verification["verified_name_count"],
            "reopen_failure_count": variable_construction_verification["failure_count"],
        }
    if variable_construction is not None:
        result["variable_construction_anchors"] = variable_construction
        result["interpretation"].append(
            "The forty-fourth database revision also contains the separately reviewed GS2 variable-construction and legacy path-resolution anchors."
        )
    script_object = None
    if args.script_object_anchors or args.script_object_verification:
        if not args.script_object_anchors or not args.script_object_verification:
            raise ValueError(
                "script-object anchors and script-object verification must be supplied together"
            )
        script_object_document = load(args.script_object_anchors)
        script_object_verification = load(args.script_object_verification)
        if script_object_document.get("artifact") != "spectron_script_object_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-object anchor artifact")
        if not script_object_verification.get("verified"):
            raise ValueError("script-object anchor reopen verification did not pass")
        expected_script_object = len(script_object_document["anchors"])
        if script_object_verification["verified_name_count"] != expected_script_object:
            raise ValueError("script-object verification count differs from artifact")
        script_object = {
            "anchor_path": str(args.script_object_anchors),
            "anchor_sha256": sha256_path(args.script_object_anchors),
            "reopen_verification": str(args.script_object_verification),
            "anchor_count": expected_script_object,
            "verified_name_count": script_object_verification["verified_name_count"],
            "reopen_failure_count": script_object_verification["failure_count"],
        }
    if script_object is not None:
        result["script_object_anchors"] = script_object
        result["interpretation"].append(
            "The forty-fifth database revision also contains the separately reviewed GS2 script diagnostic and object-creation anchors."
        )
    script_state = None
    if args.script_state_anchors or args.script_state_verification:
        if not args.script_state_anchors or not args.script_state_verification:
            raise ValueError(
                "script-state anchors and script-state verification must be supplied together"
            )
        script_state_document = load(args.script_state_anchors)
        script_state_verification = load(args.script_state_verification)
        if script_state_document.get("artifact") != "spectron_script_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-state anchor artifact")
        if not script_state_verification.get("verified"):
            raise ValueError("script-state anchor reopen verification did not pass")
        expected_script_state = len(script_state_document["anchors"])
        if script_state_verification["verified_name_count"] != expected_script_state:
            raise ValueError("script-state verification count differs from artifact")
        script_state = {
            "anchor_path": str(args.script_state_anchors),
            "anchor_sha256": sha256_path(args.script_state_anchors),
            "reopen_verification": str(args.script_state_verification),
            "anchor_count": expected_script_state,
            "verified_name_count": script_state_verification["verified_name_count"],
            "reopen_failure_count": script_state_verification["failure_count"],
        }
    if script_state is not None:
        result["script_state_anchors"] = script_state
        result["interpretation"].append(
            "The forty-sixth database revision also contains the separately reviewed GS2 profiling and player-flag state anchors."
        )
    execution_dispatch = None
    if args.execution_dispatch_anchors or args.execution_dispatch_verification:
        if not args.execution_dispatch_anchors or not args.execution_dispatch_verification:
            raise ValueError(
                "execution-dispatch anchors and execution-dispatch verification must be supplied together"
            )
        execution_dispatch_document = load(args.execution_dispatch_anchors)
        execution_dispatch_verification = load(args.execution_dispatch_verification)
        if execution_dispatch_document.get("artifact") != "spectron_execution_dispatch_manual_translation_anchors_20260826":
            raise ValueError("unexpected execution-dispatch anchor artifact")
        if not execution_dispatch_verification.get("verified"):
            raise ValueError("execution-dispatch anchor reopen verification did not pass")
        expected_execution_dispatch = len(execution_dispatch_document["anchors"])
        if execution_dispatch_verification["verified_name_count"] != expected_execution_dispatch:
            raise ValueError("execution-dispatch verification count differs from artifact")
        execution_dispatch = {
            "anchor_path": str(args.execution_dispatch_anchors),
            "anchor_sha256": sha256_path(args.execution_dispatch_anchors),
            "reopen_verification": str(args.execution_dispatch_verification),
            "anchor_count": expected_execution_dispatch,
            "verified_name_count": execution_dispatch_verification["verified_name_count"],
            "reopen_failure_count": execution_dispatch_verification["failure_count"],
        }
    if execution_dispatch is not None:
        result["execution_dispatch_anchors"] = execution_dispatch
        result["interpretation"].append(
            "The forty-seventh database revision also contains the separately reviewed GS2 script-call and native-dispatch anchors."
        )
    tokenizer = None
    if args.tokenizer_anchors or args.tokenizer_verification:
        if not args.tokenizer_anchors or not args.tokenizer_verification:
            raise ValueError(
                "tokenizer anchors and tokenizer verification must be supplied together"
            )
        tokenizer_document = load(args.tokenizer_anchors)
        tokenizer_verification = load(args.tokenizer_verification)
        if tokenizer_document.get("artifact") != "spectron_tokenizer_manual_translation_anchors_20260826":
            raise ValueError("unexpected tokenizer anchor artifact")
        if not tokenizer_verification.get("verified"):
            raise ValueError("tokenizer anchor reopen verification did not pass")
        expected_tokenizer = len(tokenizer_document["anchors"])
        if tokenizer_verification["verified_name_count"] != expected_tokenizer:
            raise ValueError("tokenizer verification count differs from artifact")
        tokenizer = {
            "anchor_path": str(args.tokenizer_anchors),
            "anchor_sha256": sha256_path(args.tokenizer_anchors),
            "reopen_verification": str(args.tokenizer_verification),
            "anchor_count": expected_tokenizer,
            "verified_name_count": tokenizer_verification["verified_name_count"],
            "reopen_failure_count": tokenizer_verification["failure_count"],
        }
    if tokenizer is not None:
        result["tokenizer_anchors"] = tokenizer
        result["interpretation"].append(
            "The forty-eighth database revision also contains the separately reviewed GS2 tokenized string array anchor."
        )
    script_executor = None
    if args.script_executor_anchors or args.script_executor_verification:
        if not args.script_executor_anchors or not args.script_executor_verification:
            raise ValueError(
                "script-executor anchors and script-executor verification must be supplied together"
            )
        script_executor_document = load(args.script_executor_anchors)
        script_executor_verification = load(args.script_executor_verification)
        if script_executor_document.get("artifact") != "spectron_script_executor_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-executor anchor artifact")
        if not script_executor_verification.get("verified"):
            raise ValueError("script-executor anchor reopen verification did not pass")
        expected_script_executor = len(script_executor_document["anchors"])
        if script_executor_verification["verified_name_count"] != expected_script_executor:
            raise ValueError("script-executor verification count differs from artifact")
        script_executor = {
            "anchor_path": str(args.script_executor_anchors),
            "anchor_sha256": sha256_path(args.script_executor_anchors),
            "reopen_verification": str(args.script_executor_verification),
            "anchor_count": expected_script_executor,
            "verified_name_count": script_executor_verification["verified_name_count"],
            "reopen_failure_count": script_executor_verification["failure_count"],
        }
    if script_executor is not None:
        result["script_executor_anchors"] = script_executor
        result["interpretation"].append(
            "The forty-ninth database revision also contains the separately reviewed GS2 bytecode execution-loop anchor."
        )
    script_property = None
    if args.script_property_anchors or args.script_property_verification:
        if not args.script_property_anchors or not args.script_property_verification:
            raise ValueError(
                "script-property anchors and script-property verification must be supplied together"
            )
        script_property_document = load(args.script_property_anchors)
        script_property_verification = load(args.script_property_verification)
        if script_property_document.get("artifact") != "spectron_script_property_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-property anchor artifact")
        if not script_property_verification.get("verified"):
            raise ValueError("script-property anchor reopen verification did not pass")
        expected_script_property = len(script_property_document["anchors"])
        if script_property_verification["verified_name_count"] != expected_script_property:
            raise ValueError("script-property verification count differs from artifact")
        script_property = {
            "anchor_path": str(args.script_property_anchors),
            "anchor_sha256": sha256_path(args.script_property_anchors),
            "reopen_verification": str(args.script_property_verification),
            "anchor_count": expected_script_property,
            "verified_name_count": script_property_verification["verified_name_count"],
            "reopen_failure_count": script_property_verification["failure_count"],
        }
    if script_property is not None:
        result["script_property_anchors"] = script_property
        result["interpretation"].append(
            "The fiftieth database revision also contains the separately reviewed GS2 typed property access and registration anchors."
        )
    script_universe = None
    if args.script_universe_anchors or args.script_universe_verification:
        if not args.script_universe_anchors or not args.script_universe_verification:
            raise ValueError(
                "script-universe anchors and script-universe verification must be supplied together"
            )
        script_universe_document = load(args.script_universe_anchors)
        script_universe_verification = load(args.script_universe_verification)
        if script_universe_document.get("artifact") != "spectron_script_universe_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-universe anchor artifact")
        if not script_universe_verification.get("verified"):
            raise ValueError("script-universe anchor reopen verification did not pass")
        expected_script_universe = len(script_universe_document["anchors"])
        if script_universe_verification["verified_name_count"] != expected_script_universe:
            raise ValueError("script-universe verification count differs from artifact")
        script_universe = {
            "anchor_path": str(args.script_universe_anchors),
            "anchor_sha256": sha256_path(args.script_universe_anchors),
            "reopen_verification": str(args.script_universe_verification),
            "anchor_count": expected_script_universe,
            "verified_name_count": script_universe_verification["verified_name_count"],
            "reopen_failure_count": script_universe_verification["failure_count"],
        }
    if script_universe is not None:
        result["script_universe_anchors"] = script_universe
        result["interpretation"].append(
            "The fifty-first database revision also contains the separately reviewed GS2 universe, class, and zipped-script anchors."
        )
    static_json_tiles = None
    if args.static_json_tiles_anchors or args.static_json_tiles_verification:
        if not args.static_json_tiles_anchors or not args.static_json_tiles_verification:
            raise ValueError(
                "static/JSON/tiles anchors and static/JSON/tiles verification must be supplied together"
            )
        static_json_tiles_document = load(args.static_json_tiles_anchors)
        static_json_tiles_verification = load(args.static_json_tiles_verification)
        if static_json_tiles_document.get("artifact") != "spectron_static_json_tiles_manual_translation_anchors_20260826":
            raise ValueError("unexpected static/JSON/tiles anchor artifact")
        if not static_json_tiles_verification.get("verified"):
            raise ValueError("static/JSON/tiles anchor reopen verification did not pass")
        expected_static_json_tiles = len(static_json_tiles_document["anchors"])
        if static_json_tiles_verification["verified_name_count"] != expected_static_json_tiles:
            raise ValueError("static/JSON/tiles verification count differs from artifact")
        static_json_tiles = {
            "anchor_path": str(args.static_json_tiles_anchors),
            "anchor_sha256": sha256_path(args.static_json_tiles_anchors),
            "reopen_verification": str(args.static_json_tiles_verification),
            "anchor_count": expected_static_json_tiles,
            "verified_name_count": static_json_tiles_verification["verified_name_count"],
            "reopen_failure_count": static_json_tiles_verification["failure_count"],
        }
    if static_json_tiles is not None:
        result["static_json_tiles_anchors"] = static_json_tiles
        result["interpretation"].append(
            "The fifty-second database revision also contains the separately reviewed static-variable, JSON-serialization, and tile-definition anchors."
        )
    tiles_update = None
    if args.tiles_update_anchors or args.tiles_update_verification:
        if not args.tiles_update_anchors or not args.tiles_update_verification:
            raise ValueError(
                "tiles-update anchors and tiles-update verification must be supplied together"
            )
        tiles_update_document = load(args.tiles_update_anchors)
        tiles_update_verification = load(args.tiles_update_verification)
        if tiles_update_document.get("artifact") != "spectron_tiles_update_manual_translation_anchors_20260826":
            raise ValueError("unexpected tiles-update anchor artifact")
        if not tiles_update_verification.get("verified"):
            raise ValueError("tiles-update anchor reopen verification did not pass")
        expected_tiles_update = len(tiles_update_document["anchors"])
        if tiles_update_verification["verified_name_count"] != expected_tiles_update:
            raise ValueError("tiles-update verification count differs from artifact")
        tiles_update = {
            "anchor_path": str(args.tiles_update_anchors),
            "anchor_sha256": sha256_path(args.tiles_update_anchors),
            "reopen_verification": str(args.tiles_update_verification),
            "anchor_count": expected_tiles_update,
            "verified_name_count": tiles_update_verification["verified_name_count"],
            "reopen_failure_count": tiles_update_verification["failure_count"],
        }
    if tiles_update is not None:
        result["tiles_update_anchors"] = tiles_update
        result["interpretation"].append(
            "The fifty-third database revision also contains the separately reviewed tile selection, definition-update, temporary-tile, and screen-rendering anchors."
        )
    particle = None
    if args.particle_anchors or args.particle_verification:
        if not args.particle_anchors or not args.particle_verification:
            raise ValueError(
                "particle anchors and particle verification must be supplied together"
            )
        particle_document = load(args.particle_anchors)
        particle_verification = load(args.particle_verification)
        if particle_document.get("artifact") != "spectron_particle_manual_translation_anchors_20260826":
            raise ValueError("unexpected particle anchor artifact")
        if not particle_verification.get("verified"):
            raise ValueError("particle anchor reopen verification did not pass")
        expected_particle = len(particle_document["anchors"])
        if particle_verification["verified_name_count"] != expected_particle:
            raise ValueError("particle verification count differs from artifact")
        particle = {
            "anchor_path": str(args.particle_anchors),
            "anchor_sha256": sha256_path(args.particle_anchors),
            "reopen_verification": str(args.particle_verification),
            "anchor_count": expected_particle,
            "verified_name_count": particle_verification["verified_name_count"],
            "reopen_failure_count": particle_verification["failure_count"],
        }
    if particle is not None:
        result["particle_anchors"] = particle
        result["interpretation"].append(
            "The fifty-fourth database revision also contains the separately reviewed particle animation, appearance, and polygon anchors."
        )
    showimg = None
    if args.showimg_anchors or args.showimg_verification:
        if not args.showimg_anchors or not args.showimg_verification:
            raise ValueError(
                "ShowImg anchors and ShowImg verification must be supplied together"
            )
        showimg_document = load(args.showimg_anchors)
        showimg_verification = load(args.showimg_verification)
        if showimg_document.get("artifact") != "spectron_showimg_manual_translation_anchors_20260826":
            raise ValueError("unexpected ShowImg anchor artifact")
        if not showimg_verification.get("verified"):
            raise ValueError("ShowImg anchor reopen verification did not pass")
        expected_showimg = len(showimg_document["anchors"])
        if showimg_verification["verified_name_count"] != expected_showimg:
            raise ValueError("ShowImg verification count differs from artifact")
        showimg = {
            "anchor_path": str(args.showimg_anchors),
            "anchor_sha256": sha256_path(args.showimg_anchors),
            "reopen_verification": str(args.showimg_verification),
            "anchor_count": expected_showimg,
            "verified_name_count": showimg_verification["verified_name_count"],
            "reopen_failure_count": showimg_verification["failure_count"],
        }
    if showimg is not None:
        result["showimg_anchors"] = showimg
        result["interpretation"].append(
            "The fifty-fifth database revision also contains the separately reviewed TShowImg serialization and network-property anchors."
        )
    showimg_property = None
    if args.showimg_property_anchors or args.showimg_property_verification:
        if not args.showimg_property_anchors or not args.showimg_property_verification:
            raise ValueError(
                "ShowImg property anchors and ShowImg property verification must be supplied together"
            )
        showimg_property_document = load(args.showimg_property_anchors)
        showimg_property_verification = load(args.showimg_property_verification)
        if showimg_property_document.get("artifact") != "spectron_showimg_property_manual_translation_anchors_20260827":
            raise ValueError("unexpected ShowImg property anchor artifact")
        if not showimg_property_verification.get("verified"):
            raise ValueError("ShowImg property anchor reopen verification did not pass")
        expected_showimg_property = len(showimg_property_document["anchors"])
        if showimg_property_verification["verified_name_count"] != expected_showimg_property:
            raise ValueError("ShowImg property verification count differs from artifact")
        showimg_property = {
            "anchor_path": str(args.showimg_property_anchors),
            "anchor_sha256": sha256_path(args.showimg_property_anchors),
            "reopen_verification": str(args.showimg_property_verification),
            "anchor_count": expected_showimg_property,
            "verified_name_count": showimg_property_verification["verified_name_count"],
            "reopen_failure_count": showimg_property_verification["failure_count"],
        }
    if showimg_property is not None:
        result["showimg_property_anchors"] = showimg_property
        result["interpretation"].append(
            "The one-hundred-sixty-fifth database revision also contains the separately reviewed complete TShowImg property callback table anchors."
        )
    showimg_residual = None
    if args.showimg_residual_anchors or args.showimg_residual_verification:
        if not args.showimg_residual_anchors or not args.showimg_residual_verification:
            raise ValueError(
                "ShowImg residual anchors and ShowImg residual verification must be supplied together"
            )
        showimg_residual_document = load(args.showimg_residual_anchors)
        showimg_residual_verification = load(args.showimg_residual_verification)
        if showimg_residual_document.get("artifact") != "spectron_showimg_residual_manual_translation_anchors_20260827":
            raise ValueError("unexpected ShowImg residual anchor artifact")
        if not showimg_residual_verification.get("verified"):
            raise ValueError("ShowImg residual anchor reopen verification did not pass")
        expected_showimg_residual = len(showimg_residual_document["anchors"])
        if showimg_residual_verification["verified_name_count"] != expected_showimg_residual:
            raise ValueError("ShowImg residual verification count differs from artifact")
        showimg_residual = {
            "anchor_path": str(args.showimg_residual_anchors),
            "anchor_sha256": sha256_path(args.showimg_residual_anchors),
            "reopen_verification": str(args.showimg_residual_verification),
            "anchor_count": expected_showimg_residual,
            "verified_name_count": showimg_residual_verification["verified_name_count"],
            "reopen_failure_count": showimg_residual_verification["failure_count"],
        }
    if showimg_residual is not None:
        result["showimg_residual_anchors"] = showimg_residual
        result["interpretation"].append(
            "The one-hundred-sixty-sixth database revision also contains the separately reviewed residual TShowImg wrappers, helpers, and properties-class lifecycle anchors."
        )
    server_object_scalar = None
    if args.server_object_scalar_anchors or args.server_object_scalar_verification:
        if not args.server_object_scalar_anchors or not args.server_object_scalar_verification:
            raise ValueError(
                "server-object scalar anchors and server-object scalar verification must be supplied together"
            )
        server_object_scalar_document = load(args.server_object_scalar_anchors)
        server_object_scalar_verification = load(args.server_object_scalar_verification)
        if server_object_scalar_document.get("artifact") != "spectron_server_object_scalar_manual_translation_anchors_20260827":
            raise ValueError("unexpected server-object scalar anchor artifact")
        if not server_object_scalar_verification.get("verified"):
            raise ValueError("server-object scalar anchor reopen verification did not pass")
        expected_server_object_scalar = len(server_object_scalar_document["anchors"])
        if server_object_scalar_verification["verified_name_count"] != expected_server_object_scalar:
            raise ValueError("server-object scalar verification count differs from artifact")
        server_object_scalar = {
            "anchor_path": str(args.server_object_scalar_anchors),
            "anchor_sha256": sha256_path(args.server_object_scalar_anchors),
            "reopen_verification": str(args.server_object_scalar_verification),
            "anchor_count": expected_server_object_scalar,
            "verified_name_count": server_object_scalar_verification["verified_name_count"],
            "reopen_failure_count": server_object_scalar_verification["failure_count"],
        }
    if server_object_scalar is not None:
        result["server_object_scalar_anchors"] = server_object_scalar
        result["interpretation"].append(
            "The one-hundred-sixty-seventh database revision also contains the separately reviewed exact-shape server-object scalar and constructor anchors."
        )
    compression = None
    if args.compression_anchors or args.compression_verification:
        if not args.compression_anchors or not args.compression_verification:
            raise ValueError(
                "compression anchors and compression verification must be supplied together"
            )
        compression_document = load(args.compression_anchors)
        compression_verification = load(args.compression_verification)
        if compression_document.get("artifact") != "spectron_compression_manual_translation_anchors_20260827":
            raise ValueError("unexpected compression anchor artifact")
        if not compression_verification.get("verified"):
            raise ValueError("compression anchor reopen verification did not pass")
        expected_compression = len(compression_document["anchors"])
        if compression_verification["verified_name_count"] != expected_compression:
            raise ValueError("compression verification count differs from artifact")
        compression = {
            "anchor_path": str(args.compression_anchors),
            "anchor_sha256": sha256_path(args.compression_anchors),
            "reopen_verification": str(args.compression_verification),
            "anchor_count": expected_compression,
            "verified_name_count": compression_verification["verified_name_count"],
            "reopen_failure_count": compression_verification["failure_count"],
        }
    if compression is not None:
        result["compression_anchors"] = compression
        result["interpretation"].append(
            "The one-hundred-sixty-eighth database revision also contains the separately reviewed exact-shape TCompression wrapper anchors."
        )
    files = None
    if args.files_anchors or args.files_verification:
        if not args.files_anchors or not args.files_verification:
            raise ValueError(
                "files anchors and files verification must be supplied together"
            )
        files_document = load(args.files_anchors)
        files_verification = load(args.files_verification)
        if files_document.get("artifact") != "spectron_files_manual_translation_anchors_20260827":
            raise ValueError("unexpected files anchor artifact")
        if not files_verification.get("verified"):
            raise ValueError("files anchor reopen verification did not pass")
        expected_files = len(files_document["anchors"])
        if files_verification["verified_name_count"] != expected_files:
            raise ValueError("files verification count differs from artifact")
        files = {
            "anchor_path": str(args.files_anchors),
            "anchor_sha256": sha256_path(args.files_anchors),
            "reopen_verification": str(args.files_verification),
            "anchor_count": expected_files,
            "verified_name_count": files_verification["verified_name_count"],
            "reopen_failure_count": files_verification["failure_count"],
        }
    if files is not None:
        result["files_anchors"] = files
        result["interpretation"].append(
            "The one-hundred-sixty-ninth database revision also contains the separately reviewed exact-shape TFiles helper anchors."
        )
    encryption = None
    if args.encryption_anchors or args.encryption_verification:
        if not args.encryption_anchors or not args.encryption_verification:
            raise ValueError(
                "encryption anchors and encryption verification must be supplied together"
            )
        encryption_document = load(args.encryption_anchors)
        encryption_verification = load(args.encryption_verification)
        if encryption_document.get("artifact") != "spectron_encryption_manual_translation_anchors_20260827":
            raise ValueError("unexpected encryption anchor artifact")
        if not encryption_verification.get("verified"):
            raise ValueError("encryption anchor reopen verification did not pass")
        expected_encryption = len(encryption_document["anchors"])
        if encryption_verification["verified_name_count"] != expected_encryption:
            raise ValueError("encryption verification count differs from artifact")
        encryption = {
            "anchor_path": str(args.encryption_anchors),
            "anchor_sha256": sha256_path(args.encryption_anchors),
            "reopen_verification": str(args.encryption_verification),
            "anchor_count": expected_encryption,
            "verified_name_count": encryption_verification["verified_name_count"],
            "reopen_failure_count": encryption_verification["failure_count"],
        }
    if encryption is not None:
        result["encryption_anchors"] = encryption
        result["interpretation"].append(
            "The one-hundred-seventieth database revision also contains the separately reviewed exact-shape TEncryption wrapper anchors."
        )
    tlist = None
    if args.tlist_anchors or args.tlist_verification:
        if not args.tlist_anchors or not args.tlist_verification:
            raise ValueError(
                "TList anchors and TList verification must be supplied together"
            )
        tlist_document = load(args.tlist_anchors)
        tlist_verification = load(args.tlist_verification)
        if tlist_document.get("artifact") != "spectron_tlist_manual_translation_anchors_20260827":
            raise ValueError("unexpected TList anchor artifact")
        if not tlist_verification.get("verified"):
            raise ValueError("TList anchor reopen verification did not pass")
        expected_tlist = len(tlist_document["anchors"])
        if tlist_verification["verified_name_count"] != expected_tlist:
            raise ValueError("TList verification count differs from artifact")
        tlist = {
            "anchor_path": str(args.tlist_anchors),
            "anchor_sha256": sha256_path(args.tlist_anchors),
            "reopen_verification": str(args.tlist_verification),
            "anchor_count": expected_tlist,
            "verified_name_count": tlist_verification["verified_name_count"],
            "reopen_failure_count": tlist_verification["failure_count"],
        }
    if tlist is not None:
        result["tlist_anchors"] = tlist
        result["interpretation"].append(
            "The one-hundred-seventy-first database revision also contains the separately reviewed exact-shape TList helper anchors."
        )
    sounds = None
    if args.sounds_anchors or args.sounds_verification:
        if not args.sounds_anchors or not args.sounds_verification:
            raise ValueError(
                "sound anchors and sound verification must be supplied together"
            )
        sounds_document = load(args.sounds_anchors)
        sounds_verification = load(args.sounds_verification)
        if sounds_document.get("artifact") != "spectron_sounds_manual_translation_anchors_20260827":
            raise ValueError("unexpected sound anchor artifact")
        if not sounds_verification.get("verified"):
            raise ValueError("sound anchor reopen verification did not pass")
        expected_sounds = len(sounds_document["anchors"])
        if sounds_verification["verified_name_count"] != expected_sounds:
            raise ValueError("sound verification count differs from artifact")
        sounds = {
            "anchor_path": str(args.sounds_anchors),
            "anchor_sha256": sha256_path(args.sounds_anchors),
            "reopen_verification": str(args.sounds_verification),
            "anchor_count": expected_sounds,
            "verified_name_count": sounds_verification["verified_name_count"],
            "reopen_failure_count": sounds_verification["failure_count"],
        }
    if sounds is not None:
        result["sounds_anchors"] = sounds
        result["interpretation"].append(
            "The one-hundred-seventy-second database revision also contains the separately reviewed exact-shape TSounds helper anchors."
        )
    hash_container = None
    if args.hash_container_anchors or args.hash_container_verification:
        if not args.hash_container_anchors or not args.hash_container_verification:
            raise ValueError(
                "hash-container anchors and hash-container verification must be supplied together"
            )
        hash_container_document = load(args.hash_container_anchors)
        hash_container_verification = load(args.hash_container_verification)
        if hash_container_document.get("artifact") != "spectron_hash_container_manual_translation_anchors_20260827":
            raise ValueError("unexpected hash-container anchor artifact")
        if not hash_container_verification.get("verified"):
            raise ValueError("hash-container anchor reopen verification did not pass")
        expected_hash_container = len(hash_container_document["anchors"])
        if hash_container_verification["verified_name_count"] != expected_hash_container:
            raise ValueError("hash-container verification count differs from artifact")
        hash_container = {
            "anchor_path": str(args.hash_container_anchors),
            "anchor_sha256": sha256_path(args.hash_container_anchors),
            "reopen_verification": str(args.hash_container_verification),
            "anchor_count": expected_hash_container,
            "verified_name_count": hash_container_verification["verified_name_count"],
            "reopen_failure_count": hash_container_verification["failure_count"],
        }
    if hash_container is not None:
        result["hash_container_anchors"] = hash_container
        result["interpretation"].append(
            "The one-hundred-seventy-third database revision also contains the separately reviewed exact-shape THashList and THashStrings anchors."
        )
    tstring = None
    if args.tstring_anchors or args.tstring_verification:
        if not args.tstring_anchors or not args.tstring_verification:
            raise ValueError(
                "TString anchors and TString verification must be supplied together"
            )
        tstring_document = load(args.tstring_anchors)
        tstring_verification = load(args.tstring_verification)
        if tstring_document.get("artifact") != "spectron_tstring_manual_translation_anchors_20260827":
            raise ValueError("unexpected TString anchor artifact")
        if not tstring_verification.get("verified"):
            raise ValueError("TString anchor reopen verification did not pass")
        expected_tstring = len(tstring_document["anchors"])
        if tstring_verification["verified_name_count"] != expected_tstring:
            raise ValueError("TString verification count differs from artifact")
        tstring = {
            "anchor_path": str(args.tstring_anchors),
            "anchor_sha256": sha256_path(args.tstring_anchors),
            "reopen_verification": str(args.tstring_verification),
            "anchor_count": expected_tstring,
            "verified_name_count": tstring_verification["verified_name_count"],
            "reopen_failure_count": tstring_verification["failure_count"],
        }
    if tstring is not None:
        result["tstring_anchors"] = tstring
        result["interpretation"].append(
            "The one-hundred-seventy-fourth database revision also contains the separately reviewed exact-shape TString helper anchors."
        )
    tstring_clear = None
    if args.tstring_clear_anchors or args.tstring_clear_verification:
        if not args.tstring_clear_anchors or not args.tstring_clear_verification:
            raise ValueError(
                "TString clear anchors and TString clear verification must be supplied together"
            )
        tstring_clear_document = load(args.tstring_clear_anchors)
        tstring_clear_verification = load(args.tstring_clear_verification)
        if tstring_clear_document.get("artifact") != "spectron_tstring_clear_manual_translation_anchors_20260827":
            raise ValueError("unexpected TString clear anchor artifact")
        if not tstring_clear_verification.get("verified"):
            raise ValueError("TString clear anchor reopen verification did not pass")
        expected_tstring_clear = len(tstring_clear_document["anchors"])
        if tstring_clear_verification["verified_name_count"] != expected_tstring_clear:
            raise ValueError("TString clear verification count differs from artifact")
        tstring_clear = {
            "anchor_path": str(args.tstring_clear_anchors),
            "anchor_sha256": sha256_path(args.tstring_clear_anchors),
            "reopen_verification": str(args.tstring_clear_verification),
            "anchor_count": expected_tstring_clear,
            "verified_name_count": tstring_clear_verification["verified_name_count"],
            "reopen_failure_count": tstring_clear_verification["failure_count"],
        }
    if tstring_clear is not None:
        result["tstring_clear_anchors"] = tstring_clear
        result["interpretation"].append(
            "The one-hundred-seventy-fifth database revision also contains the separately reviewed exact-shape TString clear anchor."
        )
    static_clear = None
    if args.static_clear_anchors or args.static_clear_verification:
        if not args.static_clear_anchors or not args.static_clear_verification:
            raise ValueError(
                "static-clear anchors and static-clear verification must be supplied together"
            )
        static_clear_document = load(args.static_clear_anchors)
        static_clear_verification = load(args.static_clear_verification)
        if static_clear_document.get("artifact") != "spectron_static_clear_manual_translation_anchors_20260827":
            raise ValueError("unexpected static-clear anchor artifact")
        if not static_clear_verification.get("verified"):
            raise ValueError("static-clear anchor reopen verification did not pass")
        expected_static_clear = len(static_clear_document["anchors"])
        if static_clear_verification["verified_name_count"] != expected_static_clear:
            raise ValueError("static-clear verification count differs from artifact")
        static_clear = {
            "anchor_path": str(args.static_clear_anchors),
            "anchor_sha256": sha256_path(args.static_clear_anchors),
            "reopen_verification": str(args.static_clear_verification),
            "anchor_count": expected_static_clear,
            "verified_name_count": static_clear_verification["verified_name_count"],
            "reopen_failure_count": static_clear_verification["failure_count"],
        }
    if static_clear is not None:
        result["static_clear_anchors"] = static_clear
        result["interpretation"].append(
            "The one-hundred-seventy-sixth database revision also contains the separately reviewed TClient and TSocket static cleanup layout anchors."
        )
    particle_emitter = None
    if args.particle_emitter_anchors or args.particle_emitter_verification:
        if not args.particle_emitter_anchors or not args.particle_emitter_verification:
            raise ValueError(
                "particle-emitter anchors and particle-emitter verification must be supplied together"
            )
        particle_emitter_document = load(args.particle_emitter_anchors)
        particle_emitter_verification = load(args.particle_emitter_verification)
        if particle_emitter_document.get("artifact") != "spectron_particle_emitter_manual_translation_anchors_20260826":
            raise ValueError("unexpected particle-emitter anchor artifact")
        if not particle_emitter_verification.get("verified"):
            raise ValueError("particle-emitter anchor reopen verification did not pass")
        expected_particle_emitter = len(particle_emitter_document["anchors"])
        if particle_emitter_verification["verified_name_count"] != expected_particle_emitter:
            raise ValueError("particle-emitter verification count differs from artifact")
        particle_emitter = {
            "anchor_path": str(args.particle_emitter_anchors),
            "anchor_sha256": sha256_path(args.particle_emitter_anchors),
            "reopen_verification": str(args.particle_emitter_verification),
            "anchor_count": expected_particle_emitter,
            "verified_name_count": particle_emitter_verification["verified_name_count"],
            "reopen_failure_count": particle_emitter_verification["failure_count"],
        }
    if particle_emitter is not None:
        result["particle_emitter_anchors"] = particle_emitter
        result["interpretation"].append(
            "The fifty-sixth database revision also contains the separately reviewed particle-emitter initializer and emission anchors."
        )
    particle_emitter_script_vars = None
    if (
        args.particle_emitter_script_vars_anchors
        or args.particle_emitter_script_vars_verification
    ):
        if (
            not args.particle_emitter_script_vars_anchors
            or not args.particle_emitter_script_vars_verification
        ):
            raise ValueError(
                "particle-emitter script-vars anchors and verification must be supplied together"
            )
        particle_emitter_script_vars_document = load(
            args.particle_emitter_script_vars_anchors
        )
        particle_emitter_script_vars_verification = load(
            args.particle_emitter_script_vars_verification
        )
        if (
            particle_emitter_script_vars_document.get("artifact")
            != "spectron_particle_emitter_script_vars_manual_translation_anchors_20260827"
        ):
            raise ValueError(
                "unexpected particle-emitter script-vars anchor artifact"
            )
        if not particle_emitter_script_vars_verification.get("verified"):
            raise ValueError(
                "particle-emitter script-vars anchor reopen verification did not pass"
            )
        expected_particle_emitter_script_vars = len(
            particle_emitter_script_vars_document["anchors"]
        )
        if (
            particle_emitter_script_vars_verification["verified_name_count"]
            != expected_particle_emitter_script_vars
        ):
            raise ValueError(
                "particle-emitter script-vars verification count differs from artifact"
            )
        particle_emitter_script_vars = {
            "anchor_path": str(args.particle_emitter_script_vars_anchors),
            "anchor_sha256": sha256_path(
                args.particle_emitter_script_vars_anchors
            ),
            "reopen_verification": str(
                args.particle_emitter_script_vars_verification
            ),
            "anchor_count": expected_particle_emitter_script_vars,
            "verified_name_count": particle_emitter_script_vars_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": particle_emitter_script_vars_verification[
                "failure_count"
            ],
        }
    if particle_emitter_script_vars is not None:
        result["particle_emitter_script_vars_anchors"] = particle_emitter_script_vars
        result["interpretation"].append(
            "The one-hundred-eighty-sixth database revision also contains the separately reviewed particle-emitter script-property initializer anchor."
        )
    resource_link_lists = None
    if args.resource_link_lists_anchors or args.resource_link_lists_verification:
        if not args.resource_link_lists_anchors or not args.resource_link_lists_verification:
            raise ValueError(
                "resource link-list anchors and verification must be supplied together"
            )
        resource_link_lists_document = load(args.resource_link_lists_anchors)
        resource_link_lists_verification = load(args.resource_link_lists_verification)
        if (
            resource_link_lists_document.get("artifact")
            != "spectron_resource_link_lists_manual_translation_anchors_20260827"
        ):
            raise ValueError("unexpected resource link-list anchor artifact")
        if not resource_link_lists_verification.get("verified"):
            raise ValueError(
                "resource link-list anchor reopen verification did not pass"
            )
        expected_resource_link_lists = len(resource_link_lists_document["anchors"])
        if (
            resource_link_lists_verification["verified_name_count"]
            != expected_resource_link_lists
        ):
            raise ValueError(
                "resource link-list verification count differs from artifact"
            )
        resource_link_lists = {
            "anchor_path": str(args.resource_link_lists_anchors),
            "anchor_sha256": sha256_path(args.resource_link_lists_anchors),
            "reopen_verification": str(args.resource_link_lists_verification),
            "anchor_count": expected_resource_link_lists,
            "verified_name_count": resource_link_lists_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": resource_link_lists_verification[
                "failure_count"
            ],
        }
    if resource_link_lists is not None:
        result["resource_link_lists_anchors"] = resource_link_lists
        result["interpretation"].append(
            "The one-hundred-eighty-seventh database revision also contains the separately reviewed resource file-link and object-link list initializer anchor."
        )
    clear_cur_anis = None
    if args.clear_cur_anis_anchors or args.clear_cur_anis_verification:
        if not args.clear_cur_anis_anchors or not args.clear_cur_anis_verification:
            raise ValueError(
                "clear-cur-anis anchors and verification must be supplied together"
            )
        clear_cur_anis_document = load(args.clear_cur_anis_anchors)
        clear_cur_anis_verification = load(args.clear_cur_anis_verification)
        if (
            clear_cur_anis_document.get("artifact")
            != "spectron_clear_cur_anis_manual_translation_anchors_20260827"
        ):
            raise ValueError("unexpected clear-cur-anis anchor artifact")
        if not clear_cur_anis_verification.get("verified"):
            raise ValueError(
                "clear-cur-anis anchor reopen verification did not pass"
            )
        expected_clear_cur_anis = len(clear_cur_anis_document["anchors"])
        if (
            clear_cur_anis_verification["verified_name_count"]
            != expected_clear_cur_anis
        ):
            raise ValueError(
                "clear-cur-anis verification count differs from artifact"
            )
        clear_cur_anis = {
            "anchor_path": str(args.clear_cur_anis_anchors),
            "anchor_sha256": sha256_path(args.clear_cur_anis_anchors),
            "reopen_verification": str(args.clear_cur_anis_verification),
            "anchor_count": expected_clear_cur_anis,
            "verified_name_count": clear_cur_anis_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": clear_cur_anis_verification[
                "failure_count"
            ],
        }
    if clear_cur_anis is not None:
        result["clear_cur_anis_anchors"] = clear_cur_anis
        result["interpretation"].append(
            "The one-hundred-eighty-eighth database revision also contains the separately reviewed current-animation-state cleanup anchor."
        )
    options_window_position = None
    if (
        args.options_window_position_anchors
        or args.options_window_position_verification
    ):
        if (
            not args.options_window_position_anchors
            or not args.options_window_position_verification
        ):
            raise ValueError(
                "options window-position anchors and verification must be supplied together"
            )
        options_window_position_document = load(
            args.options_window_position_anchors
        )
        options_window_position_verification = load(
            args.options_window_position_verification
        )
        if (
            options_window_position_document.get("artifact")
            != "spectron_options_window_position_manual_translation_anchors_20260827"
        ):
            raise ValueError(
                "unexpected options window-position anchor artifact"
            )
        if not options_window_position_verification.get("verified"):
            raise ValueError(
                "options window-position anchor reopen verification did not pass"
            )
        expected_options_window_position = len(
            options_window_position_document["anchors"]
        )
        if (
            options_window_position_verification["verified_name_count"]
            != expected_options_window_position
        ):
            raise ValueError(
                "options window-position verification count differs from artifact"
            )
        options_window_position = {
            "anchor_path": str(args.options_window_position_anchors),
            "anchor_sha256": sha256_path(args.options_window_position_anchors),
            "reopen_verification": str(
                args.options_window_position_verification
            ),
            "anchor_count": expected_options_window_position,
            "verified_name_count": options_window_position_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": options_window_position_verification[
                "failure_count"
            ],
        }
    if options_window_position is not None:
        result["options_window_position_anchors"] = options_window_position
        result["interpretation"].append(
            "The one-hundred-eighty-ninth database revision also contains the separately reviewed TOptions window-position initializer anchor."
        )
    server_animation = None
    if args.server_animation_anchors or args.server_animation_verification:
        if not args.server_animation_anchors or not args.server_animation_verification:
            raise ValueError(
                "server-animation anchors and server-animation verification must be supplied together"
            )
        server_animation_document = load(args.server_animation_anchors)
        server_animation_verification = load(args.server_animation_verification)
        if server_animation_document.get("artifact") != "spectron_server_animation_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-animation anchor artifact")
        if not server_animation_verification.get("verified"):
            raise ValueError("server-animation anchor reopen verification did not pass")
        expected_server_animation = len(server_animation_document["anchors"])
        if server_animation_verification["verified_name_count"] != expected_server_animation:
            raise ValueError("server-animation verification count differs from artifact")
        server_animation = {
            "anchor_path": str(args.server_animation_anchors),
            "anchor_sha256": sha256_path(args.server_animation_anchors),
            "reopen_verification": str(args.server_animation_verification),
            "anchor_count": expected_server_animation,
            "verified_name_count": server_animation_verification["verified_name_count"],
            "reopen_failure_count": server_animation_verification["failure_count"],
        }
    if server_animation is not None:
        result["server_animation_anchors"] = server_animation
        result["interpretation"].append(
            "The fifty-seventh database revision also contains the separately reviewed explosion, carry, and flying server-animation anchors."
        )
    player_lifecycle = None
    if args.player_lifecycle_anchors or args.player_lifecycle_verification:
        if not args.player_lifecycle_anchors or not args.player_lifecycle_verification:
            raise ValueError(
                "player-lifecycle anchors and player-lifecycle verification must be supplied together"
            )
        player_lifecycle_document = load(args.player_lifecycle_anchors)
        player_lifecycle_verification = load(args.player_lifecycle_verification)
        if player_lifecycle_document.get("artifact") != "spectron_player_lifecycle_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-lifecycle anchor artifact")
        if not player_lifecycle_verification.get("verified"):
            raise ValueError("player-lifecycle anchor reopen verification did not pass")
        expected_player_lifecycle = len(player_lifecycle_document["anchors"])
        if player_lifecycle_verification["verified_name_count"] != expected_player_lifecycle:
            raise ValueError("player-lifecycle verification count differs from artifact")
        player_lifecycle = {
            "anchor_path": str(args.player_lifecycle_anchors),
            "anchor_sha256": sha256_path(args.player_lifecycle_anchors),
            "reopen_verification": str(args.player_lifecycle_verification),
            "anchor_count": expected_player_lifecycle,
            "verified_name_count": player_lifecycle_verification["verified_name_count"],
            "reopen_failure_count": player_lifecycle_verification["failure_count"],
        }
    if player_lifecycle is not None:
        result["player_lifecycle_anchors"] = player_lifecycle
        result["interpretation"].append(
            "The fifty-eighth database revision also contains the separately reviewed player start-level and periodic-update anchors."
        )
    player_emoticon = None
    if args.player_emoticon_anchors or args.player_emoticon_verification:
        if not args.player_emoticon_anchors or not args.player_emoticon_verification:
            raise ValueError(
                "player-emoticon anchors and player-emoticon verification must be supplied together"
            )
        player_emoticon_document = load(args.player_emoticon_anchors)
        player_emoticon_verification = load(args.player_emoticon_verification)
        if player_emoticon_document.get("artifact") != "spectron_player_emoticon_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-emoticon anchor artifact")
        if not player_emoticon_verification.get("verified"):
            raise ValueError("player-emoticon anchor reopen verification did not pass")
        expected_player_emoticon = len(player_emoticon_document["anchors"])
        if player_emoticon_verification["verified_name_count"] != expected_player_emoticon:
            raise ValueError("player-emoticon verification count differs from artifact")
        player_emoticon = {
            "anchor_path": str(args.player_emoticon_anchors),
            "anchor_sha256": sha256_path(args.player_emoticon_anchors),
            "reopen_verification": str(args.player_emoticon_verification),
            "anchor_count": expected_player_emoticon,
            "verified_name_count": player_emoticon_verification["verified_name_count"],
            "reopen_failure_count": player_emoticon_verification["failure_count"],
        }
    if player_emoticon is not None:
        result["player_emoticon_anchors"] = player_emoticon
        result["interpretation"].append(
            "The fifty-ninth database revision also contains the separately reviewed player emoticon-coordinate getter anchors."
        )
    player_level_entry = None
    if args.player_level_entry_anchors or args.player_level_entry_verification:
        if not args.player_level_entry_anchors or not args.player_level_entry_verification:
            raise ValueError(
                "player-level-entry anchors and player-level-entry verification must be supplied together"
            )
        player_level_entry_document = load(args.player_level_entry_anchors)
        player_level_entry_verification = load(args.player_level_entry_verification)
        if player_level_entry_document.get("artifact") != "spectron_player_level_entry_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-level-entry anchor artifact")
        if not player_level_entry_verification.get("verified"):
            raise ValueError("player-level-entry anchor reopen verification did not pass")
        expected_player_level_entry = len(player_level_entry_document["anchors"])
        if player_level_entry_verification["verified_name_count"] != expected_player_level_entry:
            raise ValueError("player-level-entry verification count differs from artifact")
        player_level_entry = {
            "anchor_path": str(args.player_level_entry_anchors),
            "anchor_sha256": sha256_path(args.player_level_entry_anchors),
            "reopen_verification": str(args.player_level_entry_verification),
            "anchor_count": expected_player_level_entry,
            "verified_name_count": player_level_entry_verification["verified_name_count"],
            "reopen_failure_count": player_level_entry_verification["failure_count"],
        }
    if player_level_entry is not None:
        result["player_level_entry_anchors"] = player_level_entry
        result["interpretation"].append(
            "The sixtieth database revision also contains the separately reviewed player main-level and server-level entry anchors."
        )
    player_side_level = None
    if args.player_side_level_anchors or args.player_side_level_verification:
        if not args.player_side_level_anchors or not args.player_side_level_verification:
            raise ValueError(
                "player-side-level anchors and player-side-level verification must be supplied together"
            )
        player_side_level_document = load(args.player_side_level_anchors)
        player_side_level_verification = load(args.player_side_level_verification)
        if player_side_level_document.get("artifact") != "spectron_player_side_level_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-side-level anchor artifact")
        if not player_side_level_verification.get("verified"):
            raise ValueError("player-side-level anchor reopen verification did not pass")
        expected_player_side_level = len(player_side_level_document["anchors"])
        if player_side_level_verification["verified_name_count"] != expected_player_side_level:
            raise ValueError("player-side-level verification count differs from artifact")
        player_side_level = {
            "anchor_path": str(args.player_side_level_anchors),
            "anchor_sha256": sha256_path(args.player_side_level_anchors),
            "reopen_verification": str(args.player_side_level_verification),
            "anchor_count": expected_player_side_level,
            "verified_name_count": player_side_level_verification["verified_name_count"],
            "reopen_failure_count": player_side_level_verification["failure_count"],
        }
    if player_side_level is not None:
        result["player_side_level_anchors"] = player_side_level
        result["interpretation"].append(
            "The sixty-first database revision also contains the separately reviewed player side-level grid and lookup anchors."
        )
    player_map_position = None
    if args.player_map_position_anchors or args.player_map_position_verification:
        if not args.player_map_position_anchors or not args.player_map_position_verification:
            raise ValueError(
                "player-map-position anchors and player-map-position verification must be supplied together"
            )
        player_map_position_document = load(args.player_map_position_anchors)
        player_map_position_verification = load(args.player_map_position_verification)
        if player_map_position_document.get("artifact") != "spectron_player_map_position_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-map-position anchor artifact")
        if not player_map_position_verification.get("verified"):
            raise ValueError("player-map-position anchor reopen verification did not pass")
        expected_player_map_position = len(player_map_position_document["anchors"])
        if player_map_position_verification["verified_name_count"] != expected_player_map_position:
            raise ValueError("player-map-position verification count differs from artifact")
        player_map_position = {
            "anchor_path": str(args.player_map_position_anchors),
            "anchor_sha256": sha256_path(args.player_map_position_anchors),
            "reopen_verification": str(args.player_map_position_verification),
            "anchor_count": expected_player_map_position,
            "verified_name_count": player_map_position_verification["verified_name_count"],
            "reopen_failure_count": player_map_position_verification["failure_count"],
        }
    if player_map_position is not None:
        result["player_map_position_anchors"] = player_map_position
        result["interpretation"].append(
            "The sixty-second database revision also contains the separately reviewed player map-position and map-link anchors."
        )
    player_link_traversal = None
    if args.player_link_traversal_anchors or args.player_link_traversal_verification:
        if not args.player_link_traversal_anchors or not args.player_link_traversal_verification:
            raise ValueError(
                "player-link-traversal anchors and player-link-traversal verification must be supplied together"
            )
        player_link_traversal_document = load(args.player_link_traversal_anchors)
        player_link_traversal_verification = load(args.player_link_traversal_verification)
        if player_link_traversal_document.get("artifact") != "spectron_player_link_traversal_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-link-traversal anchor artifact")
        if not player_link_traversal_verification.get("verified"):
            raise ValueError("player-link-traversal anchor reopen verification did not pass")
        expected_player_link_traversal = len(player_link_traversal_document["anchors"])
        if player_link_traversal_verification["verified_name_count"] != expected_player_link_traversal:
            raise ValueError("player-link-traversal verification count differs from artifact")
        player_link_traversal = {
            "anchor_path": str(args.player_link_traversal_anchors),
            "anchor_sha256": sha256_path(args.player_link_traversal_anchors),
            "reopen_verification": str(args.player_link_traversal_verification),
            "anchor_count": expected_player_link_traversal,
            "verified_name_count": player_link_traversal_verification["verified_name_count"],
            "reopen_failure_count": player_link_traversal_verification["failure_count"],
        }
    if player_link_traversal is not None:
        result["player_link_traversal_anchors"] = player_link_traversal
        result["interpretation"].append(
            "The sixty-third database revision also contains the separately reviewed player level-animation and link-traversal anchors."
        )
    player_weapon_state = None
    if args.player_weapon_state_anchors or args.player_weapon_state_verification:
        if not args.player_weapon_state_anchors or not args.player_weapon_state_verification:
            raise ValueError(
                "player-weapon-state anchors and player-weapon-state verification must be supplied together"
            )
        player_weapon_state_document = load(args.player_weapon_state_anchors)
        player_weapon_state_verification = load(args.player_weapon_state_verification)
        if player_weapon_state_document.get("artifact") != "spectron_player_weapon_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-weapon-state anchor artifact")
        if not player_weapon_state_verification.get("verified"):
            raise ValueError("player-weapon-state anchor reopen verification did not pass")
        expected_player_weapon_state = len(player_weapon_state_document["anchors"])
        if player_weapon_state_verification["verified_name_count"] != expected_player_weapon_state:
            raise ValueError("player-weapon-state verification count differs from artifact")
        player_weapon_state = {
            "anchor_path": str(args.player_weapon_state_anchors),
            "anchor_sha256": sha256_path(args.player_weapon_state_anchors),
            "reopen_verification": str(args.player_weapon_state_verification),
            "anchor_count": expected_player_weapon_state,
            "verified_name_count": player_weapon_state_verification["verified_name_count"],
            "reopen_failure_count": player_weapon_state_verification["failure_count"],
        }
    if player_weapon_state is not None:
        result["player_weapon_state_anchors"] = player_weapon_state
        result["interpretation"].append(
            "The sixty-fourth database revision also contains the separately reviewed player attribute reset and weapon-state anchors."
        )
    player_visual_setter = None
    if args.player_visual_setter_anchors or args.player_visual_setter_verification:
        if not args.player_visual_setter_anchors or not args.player_visual_setter_verification:
            raise ValueError(
                "player-visual-setter anchors and player-visual-setter verification must be supplied together"
            )
        player_visual_setter_document = load(args.player_visual_setter_anchors)
        player_visual_setter_verification = load(args.player_visual_setter_verification)
        if player_visual_setter_document.get("artifact") != "spectron_player_visual_setter_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-visual-setter anchor artifact")
        if not player_visual_setter_verification.get("verified"):
            raise ValueError("player-visual-setter anchor reopen verification did not pass")
        expected_player_visual_setter = len(player_visual_setter_document["anchors"])
        if player_visual_setter_verification["verified_name_count"] != expected_player_visual_setter:
            raise ValueError("player-visual-setter verification count differs from artifact")
        player_visual_setter = {
            "anchor_path": str(args.player_visual_setter_anchors),
            "anchor_sha256": sha256_path(args.player_visual_setter_anchors),
            "reopen_verification": str(args.player_visual_setter_verification),
            "anchor_count": expected_player_visual_setter,
            "verified_name_count": player_visual_setter_verification["verified_name_count"],
            "reopen_failure_count": player_visual_setter_verification["failure_count"],
        }
    if player_visual_setter is not None:
        result["player_visual_setter_anchors"] = player_visual_setter
        result["interpretation"].append(
            "The sixty-fifth database revision also contains the separately reviewed player draw-rectangle and visual setter anchors."
        )
    player_movement = None
    if args.player_movement_anchors or args.player_movement_verification:
        if not args.player_movement_anchors or not args.player_movement_verification:
            raise ValueError(
                "player-movement anchors and player-movement verification must be supplied together"
            )
        player_movement_document = load(args.player_movement_anchors)
        player_movement_verification = load(args.player_movement_verification)
        if player_movement_document.get("artifact") != "spectron_player_movement_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-movement anchor artifact")
        if not player_movement_verification.get("verified"):
            raise ValueError("player-movement anchor reopen verification did not pass")
        expected_player_movement = len(player_movement_document["anchors"])
        if player_movement_verification["verified_name_count"] != expected_player_movement:
            raise ValueError("player-movement verification count differs from artifact")
        player_movement = {
            "anchor_path": str(args.player_movement_anchors),
            "anchor_sha256": sha256_path(args.player_movement_anchors),
            "reopen_verification": str(args.player_movement_verification),
            "anchor_count": expected_player_movement,
            "verified_name_count": player_movement_verification["verified_name_count"],
            "reopen_failure_count": player_movement_verification["failure_count"],
        }
    if player_movement is not None:
        result["player_movement_anchors"] = player_movement
        result["interpretation"].append(
            "The sixty-sixth database revision also contains the separately reviewed player movement, item, and hurt-handling anchors."
        )
    server_player_state = None
    if args.server_player_state_anchors or args.server_player_state_verification:
        if not args.server_player_state_anchors or not args.server_player_state_verification:
            raise ValueError(
                "server-player-state anchors and server-player-state verification must be supplied together"
            )
        server_player_state_document = load(args.server_player_state_anchors)
        server_player_state_verification = load(args.server_player_state_verification)
        if server_player_state_document.get("artifact") != "spectron_server_player_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-player-state anchor artifact")
        if not server_player_state_verification.get("verified"):
            raise ValueError("server-player-state anchor reopen verification did not pass")
        expected_server_player_state = len(server_player_state_document["anchors"])
        if server_player_state_verification["verified_name_count"] != expected_server_player_state:
            raise ValueError("server-player-state verification count differs from artifact")
        server_player_state = {
            "anchor_path": str(args.server_player_state_anchors),
            "anchor_sha256": sha256_path(args.server_player_state_anchors),
            "reopen_verification": str(args.server_player_state_verification),
            "anchor_count": expected_server_player_state,
            "verified_name_count": server_player_state_verification["verified_name_count"],
            "reopen_failure_count": server_player_state_verification["failure_count"],
        }
    if server_player_state is not None:
        result["server_player_state_anchors"] = server_player_state
        result["interpretation"].append(
            "The sixty-seventh database revision also contains the separately reviewed server-player state, property, level, nickname, and weapon-image anchors."
        )
    server_npc_state = None
    if args.server_npc_state_anchors or args.server_npc_state_verification:
        if not args.server_npc_state_anchors or not args.server_npc_state_verification:
            raise ValueError(
                "server-NPC-state anchors and server-NPC-state verification must be supplied together"
            )
        server_npc_state_document = load(args.server_npc_state_anchors)
        server_npc_state_verification = load(args.server_npc_state_verification)
        if server_npc_state_document.get("artifact") != "spectron_server_npc_state_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-NPC-state anchor artifact")
        if not server_npc_state_verification.get("verified"):
            raise ValueError("server-NPC-state anchor reopen verification did not pass")
        expected_server_npc_state = len(server_npc_state_document["anchors"])
        if server_npc_state_verification["verified_name_count"] != expected_server_npc_state:
            raise ValueError("server-NPC-state verification count differs from artifact")
        server_npc_state = {
            "anchor_path": str(args.server_npc_state_anchors),
            "anchor_sha256": sha256_path(args.server_npc_state_anchors),
            "reopen_verification": str(args.server_npc_state_verification),
            "anchor_count": expected_server_npc_state,
            "verified_name_count": server_npc_state_verification["verified_name_count"],
            "reopen_failure_count": server_npc_state_verification["failure_count"],
        }
    if server_npc_state is not None:
        result["server_npc_state_anchors"] = server_npc_state
        result["interpretation"].append(
            "The sixty-eighth database revision also contains the separately reviewed server-NPC construction, shape, naming, default-image, movement, and property anchors."
        )
    npc_accessor = None
    if args.npc_accessor_anchors or args.npc_accessor_verification:
        if not args.npc_accessor_anchors or not args.npc_accessor_verification:
            raise ValueError(
                "NPC accessor anchors and NPC accessor verification must be supplied together"
            )
        npc_accessor_document = load(args.npc_accessor_anchors)
        npc_accessor_verification = load(args.npc_accessor_verification)
        if npc_accessor_document.get("artifact") != "spectron_npc_accessor_manual_translation_anchors_20260826":
            raise ValueError("unexpected NPC accessor anchor artifact")
        if not npc_accessor_verification.get("verified"):
            raise ValueError("NPC accessor anchor reopen verification did not pass")
        expected_npc_accessor = len(npc_accessor_document["anchors"])
        if npc_accessor_verification["verified_name_count"] != expected_npc_accessor:
            raise ValueError("NPC accessor verification count differs from artifact")
        npc_accessor = {
            "anchor_path": str(args.npc_accessor_anchors),
            "anchor_sha256": sha256_path(args.npc_accessor_anchors),
            "reopen_verification": str(args.npc_accessor_verification),
            "anchor_count": expected_npc_accessor,
            "verified_name_count": npc_accessor_verification["verified_name_count"],
            "reopen_failure_count": npc_accessor_verification["failure_count"],
        }
    if npc_accessor is not None:
        result["npc_accessor_anchors"] = npc_accessor
        result["interpretation"].append(
            "The sixty-ninth database revision also contains the separately reviewed compact server-NPC accessor anchors."
        )
    npc_destructor = None
    if args.npc_destructor_anchors or args.npc_destructor_verification:
        if not args.npc_destructor_anchors or not args.npc_destructor_verification:
            raise ValueError(
                "NPC destructor anchors and NPC destructor verification must be supplied together"
            )
        npc_destructor_document = load(args.npc_destructor_anchors)
        npc_destructor_verification = load(args.npc_destructor_verification)
        if npc_destructor_document.get("artifact") != "spectron_npc_destructor_manual_translation_anchors_20260826":
            raise ValueError("unexpected NPC destructor anchor artifact")
        if not npc_destructor_verification.get("verified"):
            raise ValueError("NPC destructor anchor reopen verification did not pass")
        expected_npc_destructor = len(npc_destructor_document["anchors"])
        if npc_destructor_verification["verified_name_count"] != expected_npc_destructor:
            raise ValueError("NPC destructor verification count differs from artifact")
        npc_destructor = {
            "anchor_path": str(args.npc_destructor_anchors),
            "anchor_sha256": sha256_path(args.npc_destructor_anchors),
            "reopen_verification": str(args.npc_destructor_verification),
            "anchor_count": expected_npc_destructor,
            "verified_name_count": npc_destructor_verification["verified_name_count"],
            "reopen_failure_count": npc_destructor_verification["failure_count"],
        }
    if npc_destructor is not None:
        result["npc_destructor_anchors"] = npc_destructor
        result["interpretation"].append(
            "The seventieth database revision also contains the separately reviewed server-NPC complete and deleting destructor anchors."
        )
    server_level_property = None
    if args.server_level_property_anchors or args.server_level_property_verification:
        if not args.server_level_property_anchors or not args.server_level_property_verification:
            raise ValueError(
                "server-level property anchors and server-level property verification must be supplied together"
            )
        server_level_property_document = load(args.server_level_property_anchors)
        server_level_property_verification = load(args.server_level_property_verification)
        if server_level_property_document.get("artifact") != "spectron_server_level_property_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-level property anchor artifact")
        if not server_level_property_verification.get("verified"):
            raise ValueError("server-level property anchor reopen verification did not pass")
        expected_server_level_property = len(server_level_property_document["anchors"])
        if server_level_property_verification["verified_name_count"] != expected_server_level_property:
            raise ValueError("server-level property verification count differs from artifact")
        server_level_property = {
            "anchor_path": str(args.server_level_property_anchors),
            "anchor_sha256": sha256_path(args.server_level_property_anchors),
            "reopen_verification": str(args.server_level_property_verification),
            "anchor_count": expected_server_level_property,
            "verified_name_count": server_level_property_verification["verified_name_count"],
            "reopen_failure_count": server_level_property_verification["failure_count"],
        }
    if server_level_property is not None:
        result["server_level_property_anchors"] = server_level_property
        result["interpretation"].append(
            "The seventy-first database revision also contains the separately reviewed compact server-level property and level-link destination anchors."
        )
    server_level_interaction = None
    if args.server_level_interaction_anchors or args.server_level_interaction_verification:
        if not args.server_level_interaction_anchors or not args.server_level_interaction_verification:
            raise ValueError(
                "server-level interaction anchors and server-level interaction verification must be supplied together"
            )
        server_level_interaction_document = load(args.server_level_interaction_anchors)
        server_level_interaction_verification = load(args.server_level_interaction_verification)
        if server_level_interaction_document.get("artifact") != "spectron_server_level_interaction_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-level interaction anchor artifact")
        if not server_level_interaction_verification.get("verified"):
            raise ValueError("server-level interaction anchor reopen verification did not pass")
        expected_server_level_interaction = len(server_level_interaction_document["anchors"])
        if server_level_interaction_verification["verified_name_count"] != expected_server_level_interaction:
            raise ValueError("server-level interaction verification count differs from artifact")
        server_level_interaction = {
            "anchor_path": str(args.server_level_interaction_anchors),
            "anchor_sha256": sha256_path(args.server_level_interaction_anchors),
            "reopen_verification": str(args.server_level_interaction_verification),
            "anchor_count": expected_server_level_interaction,
            "verified_name_count": server_level_interaction_verification["verified_name_count"],
            "reopen_failure_count": server_level_interaction_verification["failure_count"],
        }
    if server_level_interaction is not None:
        result["server_level_interaction_anchors"] = server_level_interaction
        result["interpretation"].append(
            "The seventy-second database revision also contains the separately reviewed server-level interaction, level-link coordinate, and indexed-object removal anchors."
        )
    server_level_lifecycle = None
    if args.server_level_lifecycle_anchors or args.server_level_lifecycle_verification:
        if not args.server_level_lifecycle_anchors or not args.server_level_lifecycle_verification:
            raise ValueError(
                "server-level lifecycle anchors and server-level lifecycle verification must be supplied together"
            )
        server_level_lifecycle_document = load(args.server_level_lifecycle_anchors)
        server_level_lifecycle_verification = load(args.server_level_lifecycle_verification)
        if server_level_lifecycle_document.get("artifact") != "spectron_server_level_lifecycle_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-level lifecycle anchor artifact")
        if not server_level_lifecycle_verification.get("verified"):
            raise ValueError("server-level lifecycle anchor reopen verification did not pass")
        expected_server_level_lifecycle = len(server_level_lifecycle_document["anchors"])
        if server_level_lifecycle_verification["verified_name_count"] != expected_server_level_lifecycle:
            raise ValueError("server-level lifecycle verification count differs from artifact")
        server_level_lifecycle = {
            "anchor_path": str(args.server_level_lifecycle_anchors),
            "anchor_sha256": sha256_path(args.server_level_lifecycle_anchors),
            "reopen_verification": str(args.server_level_lifecycle_verification),
            "anchor_count": expected_server_level_lifecycle,
            "verified_name_count": server_level_lifecycle_verification["verified_name_count"],
            "reopen_failure_count": server_level_lifecycle_verification["failure_count"],
        }
    if server_level_lifecycle is not None:
        result["server_level_lifecycle_anchors"] = server_level_lifecycle
        result["interpretation"].append(
            "The seventy-third database revision also contains the separately reviewed server-level deleting-destructor, script-test, and animation helper anchors."
        )
    server_level_side_helpers = None
    if args.server_level_side_helpers_anchors or args.server_level_side_helpers_verification:
        if not args.server_level_side_helpers_anchors or not args.server_level_side_helpers_verification:
            raise ValueError(
                "server-level side-helper anchors and server-level side-helper verification must be supplied together"
            )
        server_level_side_helpers_document = load(args.server_level_side_helpers_anchors)
        server_level_side_helpers_verification = load(args.server_level_side_helpers_verification)
        if server_level_side_helpers_document.get("artifact") != "spectron_server_level_side_helpers_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-level side-helper anchor artifact")
        if not server_level_side_helpers_verification.get("verified"):
            raise ValueError("server-level side-helper anchor reopen verification did not pass")
        expected_server_level_side_helpers = len(server_level_side_helpers_document["anchors"])
        if server_level_side_helpers_verification["verified_name_count"] != expected_server_level_side_helpers:
            raise ValueError("server-level side-helper verification count differs from artifact")
        server_level_side_helpers = {
            "anchor_path": str(args.server_level_side_helpers_anchors),
            "anchor_sha256": sha256_path(args.server_level_side_helpers_anchors),
            "reopen_verification": str(args.server_level_side_helpers_verification),
            "anchor_count": expected_server_level_side_helpers,
            "verified_name_count": server_level_side_helpers_verification["verified_name_count"],
            "reopen_failure_count": server_level_side_helpers_verification["failure_count"],
        }
    if server_level_side_helpers is not None:
        result["server_level_side_helpers_anchors"] = server_level_side_helpers
        result["interpretation"].append(
            "The seventy-fourth database revision also contains the separately reviewed server-level side-level position, directional lookup, and flower hook anchors."
        )
    server_level_storage = None
    if args.server_level_storage_anchors or args.server_level_storage_verification:
        if not args.server_level_storage_anchors or not args.server_level_storage_verification:
            raise ValueError(
                "server-level storage anchors and server-level storage verification must be supplied together"
            )
        server_level_storage_document = load(args.server_level_storage_anchors)
        server_level_storage_verification = load(args.server_level_storage_verification)
        if server_level_storage_document.get("artifact") != "spectron_server_level_storage_manual_translation_anchors_20260826":
            raise ValueError("unexpected server-level storage anchor artifact")
        if not server_level_storage_verification.get("verified"):
            raise ValueError("server-level storage anchor reopen verification did not pass")
        expected_server_level_storage = len(server_level_storage_document["anchors"])
        if server_level_storage_verification["verified_name_count"] != expected_server_level_storage:
            raise ValueError("server-level storage verification count differs from artifact")
        server_level_storage = {
            "anchor_path": str(args.server_level_storage_anchors),
            "anchor_sha256": sha256_path(args.server_level_storage_anchors),
            "reopen_verification": str(args.server_level_storage_verification),
            "anchor_count": expected_server_level_storage,
            "verified_name_count": server_level_storage_verification["verified_name_count"],
            "reopen_failure_count": server_level_storage_verification["failure_count"],
        }
    if server_level_storage is not None:
        result["server_level_storage_anchors"] = server_level_storage
        result["interpretation"].append(
            "The seventy-fifth database revision also contains the separately reviewed server-level constructor, encrypted storage, and player-enter dispatch anchors."
        )
    hidden_testnpc = None
    if args.hidden_testnpc_anchors or args.hidden_testnpc_verification:
        if not args.hidden_testnpc_anchors or not args.hidden_testnpc_verification:
            raise ValueError(
                "hidden testnpc anchors and hidden testnpc verification must be supplied together"
            )
        hidden_testnpc_document = load(args.hidden_testnpc_anchors)
        hidden_testnpc_verification = load(args.hidden_testnpc_verification)
        if hidden_testnpc_document.get("artifact") != "spectron_hidden_testnpc_manual_translation_anchor_20260826":
            raise ValueError("unexpected hidden testnpc anchor artifact")
        if not hidden_testnpc_verification.get("verified"):
            raise ValueError("hidden testnpc anchor reopen verification did not pass")
        expected_hidden_testnpc = len(hidden_testnpc_document["anchors"])
        if hidden_testnpc_verification["verified_name_count"] != expected_hidden_testnpc:
            raise ValueError("hidden testnpc verification count differs from artifact")
        hidden_testnpc = {
            "anchor_path": str(args.hidden_testnpc_anchors),
            "anchor_sha256": sha256_path(args.hidden_testnpc_anchors),
            "reopen_verification": str(args.hidden_testnpc_verification),
            "anchor_count": expected_hidden_testnpc,
            "verified_name_count": hidden_testnpc_verification["verified_name_count"],
            "reopen_failure_count": hidden_testnpc_verification["failure_count"],
        }
    if hidden_testnpc is not None:
        result["hidden_testnpc_anchors"] = hidden_testnpc
        result["interpretation"].append(
            "The seventy-sixth database revision also contains the separately reviewed hidden Spectron testnpc callback boundary and exact body anchor."
        )
    level_map_lookup = None
    if args.level_map_lookup_anchors or args.level_map_lookup_verification:
        if not args.level_map_lookup_anchors or not args.level_map_lookup_verification:
            raise ValueError(
                "level-map lookup anchors and level-map lookup verification must be supplied together"
            )
        level_map_lookup_document = load(args.level_map_lookup_anchors)
        level_map_lookup_verification = load(args.level_map_lookup_verification)
        if level_map_lookup_document.get("artifact") != "spectron_level_map_lookup_manual_translation_anchors_20260826":
            raise ValueError("unexpected level-map lookup anchor artifact")
        if not level_map_lookup_verification.get("verified"):
            raise ValueError("level-map lookup anchor reopen verification did not pass")
        expected_level_map_lookup = len(level_map_lookup_document["anchors"])
        if level_map_lookup_verification["verified_name_count"] != expected_level_map_lookup:
            raise ValueError("level-map lookup verification count differs from artifact")
        level_map_lookup = {
            "anchor_path": str(args.level_map_lookup_anchors),
            "anchor_sha256": sha256_path(args.level_map_lookup_anchors),
            "reopen_verification": str(args.level_map_lookup_verification),
            "anchor_count": expected_level_map_lookup,
            "verified_name_count": level_map_lookup_verification["verified_name_count"],
            "reopen_failure_count": level_map_lookup_verification["failure_count"],
        }
    if level_map_lookup is not None:
        result["level_map_lookup_anchors"] = level_map_lookup
        result["interpretation"].append(
            "The seventy-seventh database revision also contains the separately reviewed level lookup, link serialization, map selection, and GMAP loading anchors."
        )
    gani_constructor = None
    if args.gani_constructor_anchors or args.gani_constructor_verification:
        if not args.gani_constructor_anchors or not args.gani_constructor_verification:
            raise ValueError(
                "Gani constructor anchors and Gani constructor verification must be supplied together"
            )
        gani_constructor_document = load(args.gani_constructor_anchors)
        gani_constructor_verification = load(args.gani_constructor_verification)
        if gani_constructor_document.get("artifact") != "spectron_gani_constructor_manual_translation_anchor_20260826":
            raise ValueError("unexpected Gani constructor anchor artifact")
        if not gani_constructor_verification.get("verified"):
            raise ValueError("Gani constructor anchor reopen verification did not pass")
        expected_gani_constructor = len(gani_constructor_document["anchors"])
        if gani_constructor_verification["verified_name_count"] != expected_gani_constructor:
            raise ValueError("Gani constructor verification count differs from artifact")
        gani_constructor = {
            "anchor_path": str(args.gani_constructor_anchors),
            "anchor_sha256": sha256_path(args.gani_constructor_anchors),
            "reopen_verification": str(args.gani_constructor_verification),
            "anchor_count": expected_gani_constructor,
            "verified_name_count": gani_constructor_verification["verified_name_count"],
            "reopen_failure_count": gani_constructor_verification["failure_count"],
        }
    if gani_constructor is not None:
        result["gani_constructor_anchors"] = gani_constructor
        result["interpretation"].append(
            "The seventy-eighth database revision also contains the separately reviewed TGaniObject server-level constructor anchor."
        )
    gani_helper = None
    if args.gani_helper_anchors or args.gani_helper_verification:
        if not args.gani_helper_anchors or not args.gani_helper_verification:
            raise ValueError(
                "Gani helper anchors and Gani helper verification must be supplied together"
            )
        gani_helper_document = load(args.gani_helper_anchors)
        gani_helper_verification = load(args.gani_helper_verification)
        if gani_helper_document.get("artifact") != "spectron_gani_helper_manual_translation_anchors_20260826":
            raise ValueError("unexpected Gani helper anchor artifact")
        if not gani_helper_verification.get("verified"):
            raise ValueError("Gani helper anchor reopen verification did not pass")
        expected_gani_helper = len(gani_helper_document["anchors"])
        if gani_helper_verification["verified_name_count"] != expected_gani_helper:
            raise ValueError("Gani helper verification count differs from artifact")
        gani_helper = {
            "anchor_path": str(args.gani_helper_anchors),
            "anchor_sha256": sha256_path(args.gani_helper_anchors),
            "reopen_verification": str(args.gani_helper_verification),
            "anchor_count": expected_gani_helper,
            "verified_name_count": gani_helper_verification["verified_name_count"],
            "reopen_failure_count": gani_helper_verification["failure_count"],
        }
    if gani_helper is not None:
        result["gani_helper_anchors"] = gani_helper
        result["interpretation"].append(
            "The seventy-ninth database revision also contains the separately reviewed Gani color setter and sprite image-name helper anchors."
        )
    gani_runtime = None
    if args.gani_runtime_anchors or args.gani_runtime_verification:
        if not args.gani_runtime_anchors or not args.gani_runtime_verification:
            raise ValueError(
                "Gani runtime anchors and Gani runtime verification must be supplied together"
            )
        gani_runtime_document = load(args.gani_runtime_anchors)
        gani_runtime_verification = load(args.gani_runtime_verification)
        if gani_runtime_document.get("artifact") != "spectron_gani_runtime_manual_translation_anchors_20260826":
            raise ValueError("unexpected Gani runtime anchor artifact")
        if not gani_runtime_verification.get("verified"):
            raise ValueError("Gani runtime anchor reopen verification did not pass")
        expected_gani_runtime = len(gani_runtime_document["anchors"])
        if gani_runtime_verification["verified_name_count"] != expected_gani_runtime:
            raise ValueError("Gani runtime verification count differs from artifact")
        gani_runtime = {
            "anchor_path": str(args.gani_runtime_anchors),
            "anchor_sha256": sha256_path(args.gani_runtime_anchors),
            "reopen_verification": str(args.gani_runtime_verification),
            "anchor_count": expected_gani_runtime,
            "verified_name_count": gani_runtime_verification["verified_name_count"],
            "reopen_failure_count": gani_runtime_verification["failure_count"],
        }
    if gani_runtime is not None:
        result["gani_runtime_anchors"] = gani_runtime
        result["interpretation"].append(
            "The eightieth database revision also contains the separately reviewed Gani matrix, parameter, and animation-start anchors."
        )
    gani_render = None
    if args.gani_render_anchors or args.gani_render_verification:
        if not args.gani_render_anchors or not args.gani_render_verification:
            raise ValueError(
                "Gani render anchors and Gani render verification must be supplied together"
            )
        gani_render_document = load(args.gani_render_anchors)
        gani_render_verification = load(args.gani_render_verification)
        if gani_render_document.get("artifact") != "spectron_gani_render_manual_translation_anchors_20260826":
            raise ValueError("unexpected Gani render anchor artifact")
        if not gani_render_verification.get("verified"):
            raise ValueError("Gani render anchor reopen verification did not pass")
        expected_gani_render = len(gani_render_document["anchors"])
        if gani_render_verification["verified_name_count"] != expected_gani_render:
            raise ValueError("Gani render verification count differs from artifact")
        gani_render = {
            "anchor_path": str(args.gani_render_anchors),
            "anchor_sha256": sha256_path(args.gani_render_anchors),
            "reopen_verification": str(args.gani_render_verification),
            "anchor_count": expected_gani_render,
            "verified_name_count": gani_render_verification["verified_name_count"],
            "reopen_failure_count": gani_render_verification["failure_count"],
        }
    if gani_render is not None:
        result["gani_render_anchors"] = gani_render
        result["interpretation"].append(
            "The eighty-first database revision also contains the separately reviewed Gani parameter serializer, reload, and player draw anchors."
        )
    gani_frame_playback = None
    if args.gani_frame_playback_anchors or args.gani_frame_playback_verification:
        if not args.gani_frame_playback_anchors or not args.gani_frame_playback_verification:
            raise ValueError(
                "Gani frame and playback anchors and Gani frame and playback verification must be supplied together"
            )
        gani_frame_playback_document = load(args.gani_frame_playback_anchors)
        gani_frame_playback_verification = load(args.gani_frame_playback_verification)
        if gani_frame_playback_document.get("artifact") != "spectron_gani_frame_playback_manual_translation_anchors_20260826":
            raise ValueError("unexpected Gani frame and playback anchor artifact")
        if not gani_frame_playback_verification.get("verified"):
            raise ValueError("Gani frame and playback anchor reopen verification did not pass")
        expected_gani_frame_playback = len(gani_frame_playback_document["anchors"])
        if gani_frame_playback_verification["verified_name_count"] != expected_gani_frame_playback:
            raise ValueError("Gani frame and playback verification count differs from artifact")
        gani_frame_playback = {
            "anchor_path": str(args.gani_frame_playback_anchors),
            "anchor_sha256": sha256_path(args.gani_frame_playback_anchors),
            "reopen_verification": str(args.gani_frame_playback_verification),
            "anchor_count": expected_gani_frame_playback,
            "verified_name_count": gani_frame_playback_verification["verified_name_count"],
            "reopen_failure_count": gani_frame_playback_verification["failure_count"],
        }
    if gani_frame_playback is not None:
        result["gani_frame_playback_anchors"] = gani_frame_playback
        result["interpretation"].append(
            "The eighty-second database revision also contains the separately reviewed Gani frame-property and animation-playback anchors."
        )
    gani_lifecycle = None
    if args.gani_lifecycle_anchors or args.gani_lifecycle_verification:
        if not args.gani_lifecycle_anchors or not args.gani_lifecycle_verification:
            raise ValueError(
                "Gani lifecycle anchors and Gani lifecycle verification must be supplied together"
            )
        gani_lifecycle_document = load(args.gani_lifecycle_anchors)
        gani_lifecycle_verification = load(args.gani_lifecycle_verification)
        if gani_lifecycle_document.get("artifact") != "spectron_gani_lifecycle_manual_translation_anchors_20260826":
            raise ValueError("unexpected Gani lifecycle anchor artifact")
        if not gani_lifecycle_verification.get("verified"):
            raise ValueError("Gani lifecycle anchor reopen verification did not pass")
        expected_gani_lifecycle = len(gani_lifecycle_document["anchors"])
        if gani_lifecycle_verification["verified_name_count"] != expected_gani_lifecycle:
            raise ValueError("Gani lifecycle verification count differs from artifact")
        gani_lifecycle = {
            "anchor_path": str(args.gani_lifecycle_anchors),
            "anchor_sha256": sha256_path(args.gani_lifecycle_anchors),
            "reopen_verification": str(args.gani_lifecycle_verification),
            "anchor_count": expected_gani_lifecycle,
            "verified_name_count": gani_lifecycle_verification["verified_name_count"],
            "reopen_failure_count": gani_lifecycle_verification["failure_count"],
        }
    if gani_lifecycle is not None:
        result["gani_lifecycle_anchors"] = gani_lifecycle
        result["interpretation"].append(
            "The eighty-third database revision also contains the separately reviewed Gani object teardown, virtual surface, animation state, ownership, script-cache, loading, and property anchors."
        )
    tplayer_core = None
    if args.tplayer_core_anchors or args.tplayer_core_verification:
        if not args.tplayer_core_anchors or not args.tplayer_core_verification:
            raise ValueError(
                "TPlayer core anchors and TPlayer core verification must be supplied together"
            )
        tplayer_core_document = load(args.tplayer_core_anchors)
        tplayer_core_verification = load(args.tplayer_core_verification)
        if tplayer_core_document.get("artifact") != "spectron_tplayer_core_manual_translation_anchors_20260826":
            raise ValueError("unexpected TPlayer core anchor artifact")
        if not tplayer_core_verification.get("verified"):
            raise ValueError("TPlayer core anchor reopen verification did not pass")
        expected_tplayer_core = len(tplayer_core_document["anchors"])
        if tplayer_core_verification["verified_name_count"] != expected_tplayer_core:
            raise ValueError("TPlayer core verification count differs from artifact")
        tplayer_core = {
            "anchor_path": str(args.tplayer_core_anchors),
            "anchor_sha256": sha256_path(args.tplayer_core_anchors),
            "reopen_verification": str(args.tplayer_core_verification),
            "anchor_count": expected_tplayer_core,
            "verified_name_count": tplayer_core_verification["verified_name_count"],
            "reopen_failure_count": tplayer_core_verification["failure_count"],
        }
    if tplayer_core is not None:
        result["tplayer_core_anchors"] = tplayer_core
        result["interpretation"].append(
            "The eighty-fourth database revision also contains the separately reviewed TPlayer network-property serializer and constructor anchors."
        )
    resource_parser = None
    if args.resource_parser_anchors or args.resource_parser_verification:
        if not args.resource_parser_anchors or not args.resource_parser_verification:
            raise ValueError(
                "resource-parser anchors and resource-parser verification must be supplied together"
            )
        resource_parser_document = load(args.resource_parser_anchors)
        resource_parser_verification = load(args.resource_parser_verification)
        if resource_parser_document.get("artifact") != "spectron_resource_parser_manual_translation_anchors_20260826":
            raise ValueError("unexpected resource-parser anchor artifact")
        if not resource_parser_verification.get("verified"):
            raise ValueError("resource-parser anchor reopen verification did not pass")
        expected_resource_parser = len(resource_parser_document["anchors"])
        if resource_parser_verification["verified_name_count"] != expected_resource_parser:
            raise ValueError("resource-parser verification count differs from artifact")
        resource_parser = {
            "anchor_path": str(args.resource_parser_anchors),
            "anchor_sha256": sha256_path(args.resource_parser_anchors),
            "reopen_verification": str(args.resource_parser_verification),
            "anchor_count": expected_resource_parser,
            "verified_name_count": resource_parser_verification["verified_name_count"],
            "reopen_failure_count": resource_parser_verification["failure_count"],
        }
    if resource_parser is not None:
        result["resource_parser_anchors"] = resource_parser
        result["interpretation"].append(
            "The eighty-fifth database revision also contains the separately reviewed Gani lexer, cached-resource path, and update-package parser anchors."
        )
    static_utility = None
    if args.static_utility_anchors or args.static_utility_verification:
        if not args.static_utility_anchors or not args.static_utility_verification:
            raise ValueError(
                "static-utility anchors and static-utility verification must be supplied together"
            )
        static_utility_document = load(args.static_utility_anchors)
        static_utility_verification = load(args.static_utility_verification)
        if static_utility_document.get("artifact") != "spectron_static_utility_manual_translation_anchors_20260826":
            raise ValueError("unexpected static-utility anchor artifact")
        if not static_utility_verification.get("verified"):
            raise ValueError("static-utility anchor reopen verification did not pass")
        expected_static_utility = len(static_utility_document["anchors"])
        if static_utility_verification["verified_name_count"] != expected_static_utility:
            raise ValueError("static-utility verification count differs from artifact")
        static_utility = {
            "anchor_path": str(args.static_utility_anchors),
            "anchor_sha256": sha256_path(args.static_utility_anchors),
            "reopen_verification": str(args.static_utility_verification),
            "anchor_count": expected_static_utility,
            "verified_name_count": static_utility_verification["verified_name_count"],
            "reopen_failure_count": static_utility_verification["failure_count"],
        }
    if static_utility is not None:
        result["static_utility_anchors"] = static_utility
        result["interpretation"].append(
            "The eighty-sixth database revision also contains the separately reviewed statistics, profiler, GUI-style, ZIP-resource, and translation utility anchors."
        )
    font_bitmap = None
    if args.font_bitmap_anchors or args.font_bitmap_verification:
        if not args.font_bitmap_anchors or not args.font_bitmap_verification:
            raise ValueError(
                "font-bitmap anchors and font-bitmap verification must be supplied together"
            )
        font_bitmap_document = load(args.font_bitmap_anchors)
        font_bitmap_verification = load(args.font_bitmap_verification)
        if font_bitmap_document.get("artifact") != "spectron_font_bitmap_manual_translation_anchors_20260826":
            raise ValueError("unexpected font-bitmap anchor artifact")
        if not font_bitmap_verification.get("verified"):
            raise ValueError("font-bitmap anchor reopen verification did not pass")
        expected_font_bitmap = len(font_bitmap_document["anchors"])
        if font_bitmap_verification["verified_name_count"] != expected_font_bitmap:
            raise ValueError("font-bitmap verification count differs from artifact")
        font_bitmap = {
            "anchor_path": str(args.font_bitmap_anchors),
            "anchor_sha256": sha256_path(args.font_bitmap_anchors),
            "reopen_verification": str(args.font_bitmap_verification),
            "anchor_count": expected_font_bitmap,
            "verified_name_count": font_bitmap_verification["verified_name_count"],
            "reopen_failure_count": font_bitmap_verification["failure_count"],
        }
    if font_bitmap is not None:
        result["font_bitmap_anchors"] = font_bitmap
        result["interpretation"].append(
            "The eighty-seventh database revision also contains the separately reviewed font glyph, atlas, font-resource, and bitmap-loader anchors."
        )
    mng_animation = None
    if args.mng_animation_anchors or args.mng_animation_verification:
        if not args.mng_animation_anchors or not args.mng_animation_verification:
            raise ValueError(
                "MNG animation anchors and MNG animation verification must be supplied together"
            )
        mng_animation_document = load(args.mng_animation_anchors)
        mng_animation_verification = load(args.mng_animation_verification)
        if mng_animation_document.get("artifact") != "spectron_mng_animation_manual_translation_anchor_20260826":
            raise ValueError("unexpected MNG animation anchor artifact")
        if not mng_animation_verification.get("verified"):
            raise ValueError("MNG animation anchor reopen verification did not pass")
        expected_mng_animation = len(mng_animation_document["anchors"])
        if mng_animation_verification["verified_name_count"] != expected_mng_animation:
            raise ValueError("MNG animation verification count differs from artifact")
        mng_animation = {
            "anchor_path": str(args.mng_animation_anchors),
            "anchor_sha256": sha256_path(args.mng_animation_anchors),
            "reopen_verification": str(args.mng_animation_verification),
            "anchor_count": expected_mng_animation,
            "verified_name_count": mng_animation_verification["verified_name_count"],
            "reopen_failure_count": mng_animation_verification["failure_count"],
        }
    if mng_animation is not None:
        result["mng_animation_anchors"] = mng_animation
        result["interpretation"].append(
            "The eighty-eighth database revision also contains the separately reviewed MNG animation-step decoder anchor."
        )
    script_machine_tail = None
    if args.script_machine_tail_anchors or args.script_machine_tail_verification:
        if not args.script_machine_tail_anchors or not args.script_machine_tail_verification:
            raise ValueError(
                "script-machine-tail anchors and script-machine-tail verification must be supplied together"
            )
        script_machine_tail_document = load(args.script_machine_tail_anchors)
        script_machine_tail_verification = load(args.script_machine_tail_verification)
        if script_machine_tail_document.get("artifact") != "spectron_script_machine_tail_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-machine-tail anchor artifact")
        if not script_machine_tail_verification.get("verified"):
            raise ValueError("script-machine-tail anchor reopen verification did not pass")
        expected_script_machine_tail = len(script_machine_tail_document["anchors"])
        if script_machine_tail_verification["verified_name_count"] != expected_script_machine_tail:
            raise ValueError("script-machine-tail verification count differs from artifact")
        script_machine_tail = {
            "anchor_path": str(args.script_machine_tail_anchors),
            "anchor_sha256": sha256_path(args.script_machine_tail_anchors),
            "reopen_verification": str(args.script_machine_tail_verification),
            "anchor_count": expected_script_machine_tail,
            "verified_name_count": script_machine_tail_verification["verified_name_count"],
            "reopen_failure_count": script_machine_tail_verification["failure_count"],
        }
    if script_machine_tail is not None:
        result["script_machine_tail_anchors"] = script_machine_tail
        result["interpretation"].append(
            "The eighty-ninth database revision also contains the separately reviewed script-machine parameter-preparation and native callback-dispatch anchors."
        )
    script_stream_profile = None
    if args.script_stream_profile_anchors or args.script_stream_profile_verification:
        if not args.script_stream_profile_anchors or not args.script_stream_profile_verification:
            raise ValueError(
                "script-stream-profile anchors and script-stream-profile verification must be supplied together"
            )
        script_stream_profile_document = load(args.script_stream_profile_anchors)
        script_stream_profile_verification = load(args.script_stream_profile_verification)
        if script_stream_profile_document.get("artifact") != "spectron_script_stream_profile_manual_translation_anchors_20260826":
            raise ValueError("unexpected script-stream-profile anchor artifact")
        if not script_stream_profile_verification.get("verified"):
            raise ValueError("script-stream-profile anchor reopen verification did not pass")
        expected_script_stream_profile = len(script_stream_profile_document["anchors"])
        if script_stream_profile_verification["verified_name_count"] != expected_script_stream_profile:
            raise ValueError("script-stream-profile verification count differs from artifact")
        script_stream_profile = {
            "anchor_path": str(args.script_stream_profile_anchors),
            "anchor_sha256": sha256_path(args.script_stream_profile_anchors),
            "reopen_verification": str(args.script_stream_profile_verification),
            "anchor_count": expected_script_stream_profile,
            "verified_name_count": script_stream_profile_verification["verified_name_count"],
            "reopen_failure_count": script_stream_profile_verification["failure_count"],
        }
    if script_stream_profile is not None:
        result["script_stream_profile_anchors"] = script_stream_profile
        result["interpretation"].append(
            "The ninetieth database revision also contains the separately reviewed script stream parser and function/class profiler anchors."
        )
    ani_lexer = None
    if args.ani_lexer_anchors or args.ani_lexer_verification:
        if not args.ani_lexer_anchors or not args.ani_lexer_verification:
            raise ValueError(
                "animation-lexer anchors and animation-lexer verification must be supplied together"
            )
        ani_lexer_document = load(args.ani_lexer_anchors)
        ani_lexer_verification = load(args.ani_lexer_verification)
        if ani_lexer_document.get("artifact") != "spectron_ani_lexer_fatal_manual_translation_anchor_20260826":
            raise ValueError("unexpected animation-lexer anchor artifact")
        if not ani_lexer_verification.get("verified"):
            raise ValueError("animation-lexer anchor reopen verification did not pass")
        expected_ani_lexer = len(ani_lexer_document["anchors"])
        if ani_lexer_verification["verified_name_count"] != expected_ani_lexer:
            raise ValueError("animation-lexer verification count differs from artifact")
        ani_lexer = {
            "anchor_path": str(args.ani_lexer_anchors),
            "anchor_sha256": sha256_path(args.ani_lexer_anchors),
            "reopen_verification": str(args.ani_lexer_verification),
            "anchor_count": expected_ani_lexer,
            "verified_name_count": ani_lexer_verification["verified_name_count"],
            "reopen_failure_count": ani_lexer_verification["failure_count"],
        }
    if ani_lexer is not None:
        result["ani_lexer_anchors"] = ani_lexer
        result["interpretation"].append(
            "The ninety-first database revision also contains the separately reviewed generated animation-lexer fatal-exit callback anchor."
        )
    number_array_string = None
    if args.number_array_string_anchors or args.number_array_string_verification:
        if not args.number_array_string_anchors or not args.number_array_string_verification:
            raise ValueError(
                "number-array string anchors and number-array string verification must be supplied together"
            )
        number_array_string_document = load(args.number_array_string_anchors)
        number_array_string_verification = load(args.number_array_string_verification)
        if number_array_string_document.get("artifact") != "spectron_number_array_string_manual_translation_anchors_20260826":
            raise ValueError("unexpected number-array string anchor artifact")
        if not number_array_string_verification.get("verified"):
            raise ValueError("number-array string anchor reopen verification did not pass")
        expected_number_array_string = len(number_array_string_document["anchors"])
        if number_array_string_verification["verified_name_count"] != expected_number_array_string:
            raise ValueError("number-array string verification count differs from artifact")
        number_array_string = {
            "anchor_path": str(args.number_array_string_anchors),
            "anchor_sha256": sha256_path(args.number_array_string_anchors),
            "reopen_verification": str(args.number_array_string_verification),
            "anchor_count": expected_number_array_string,
            "verified_name_count": number_array_string_verification["verified_name_count"],
            "reopen_failure_count": number_array_string_verification["failure_count"],
        }
    if number_array_string is not None:
        result["number_array_string_anchors"] = number_array_string
        result["interpretation"].append(
            "The ninety-second database revision also contains the separately reviewed double and short numeric-array string-conversion anchors."
        )
    client_environment_clock = None
    if args.client_environment_clock_anchors or args.client_environment_clock_verification:
        if not args.client_environment_clock_anchors or not args.client_environment_clock_verification:
            raise ValueError(
                "client-environment clock anchors and client-environment clock verification must be supplied together"
            )
        client_environment_clock_document = load(args.client_environment_clock_anchors)
        client_environment_clock_verification = load(args.client_environment_clock_verification)
        if client_environment_clock_document.get("artifact") != "spectron_client_environment_clock_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-environment clock anchor artifact")
        if not client_environment_clock_verification.get("verified"):
            raise ValueError("client-environment clock anchor reopen verification did not pass")
        expected_client_environment_clock = len(client_environment_clock_document["anchors"])
        if client_environment_clock_verification["verified_name_count"] != expected_client_environment_clock:
            raise ValueError("client-environment clock verification count differs from artifact")
        client_environment_clock = {
            "anchor_path": str(args.client_environment_clock_anchors),
            "anchor_sha256": sha256_path(args.client_environment_clock_anchors),
            "reopen_verification": str(args.client_environment_clock_verification),
            "anchor_count": expected_client_environment_clock,
            "verified_name_count": client_environment_clock_verification["verified_name_count"],
            "reopen_failure_count": client_environment_clock_verification["failure_count"],
        }
    if client_environment_clock is not None:
        result["client_environment_clock_anchors"] = client_environment_clock
        result["interpretation"].append(
            "The ninety-third database revision also contains the separately reviewed client-environment build-time and expiry helpers."
        )
    client_var_core = None
    if args.client_var_core_anchors or args.client_var_core_verification:
        if not args.client_var_core_anchors or not args.client_var_core_verification:
            raise ValueError(
                "client-variable core anchors and client-variable core verification must be supplied together"
            )
        client_var_core_document = load(args.client_var_core_anchors)
        client_var_core_verification = load(args.client_var_core_verification)
        if client_var_core_document.get("artifact") != "spectron_client_var_core_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-variable core anchor artifact")
        if not client_var_core_verification.get("verified"):
            raise ValueError("client-variable core anchor reopen verification did not pass")
        expected_client_var_core = len(client_var_core_document["anchors"])
        if client_var_core_verification["verified_name_count"] != expected_client_var_core:
            raise ValueError("client-variable core verification count differs from artifact")
        client_var_core = {
            "anchor_path": str(args.client_var_core_anchors),
            "anchor_sha256": sha256_path(args.client_var_core_anchors),
            "reopen_verification": str(args.client_var_core_verification),
            "anchor_count": expected_client_var_core,
            "verified_name_count": client_var_core_verification["verified_name_count"],
            "reopen_failure_count": client_var_core_verification["failure_count"],
        }
    if client_var_core is not None:
        result["client_var_core_anchors"] = client_var_core
        result["interpretation"].append(
            "The ninety-fourth database revision also contains the separately reviewed TGraalClientVar send and string-update anchors."
        )
    tstringlist_comma = None
    if args.tstringlist_comma_anchors or args.tstringlist_comma_verification:
        if not args.tstringlist_comma_anchors or not args.tstringlist_comma_verification:
            raise ValueError(
                "TStringList comma anchors and TStringList comma verification must be supplied together"
            )
        tstringlist_comma_document = load(args.tstringlist_comma_anchors)
        tstringlist_comma_verification = load(args.tstringlist_comma_verification)
        if tstringlist_comma_document.get("artifact") != "spectron_tstringlist_comma_manual_translation_anchors_20260826":
            raise ValueError("unexpected TStringList comma anchor artifact")
        if not tstringlist_comma_verification.get("verified"):
            raise ValueError("TStringList comma anchor reopen verification did not pass")
        expected_tstringlist_comma = len(tstringlist_comma_document["anchors"])
        if tstringlist_comma_verification["verified_name_count"] != expected_tstringlist_comma:
            raise ValueError("TStringList comma verification count differs from artifact")
        tstringlist_comma = {
            "anchor_path": str(args.tstringlist_comma_anchors),
            "anchor_sha256": sha256_path(args.tstringlist_comma_anchors),
            "reopen_verification": str(args.tstringlist_comma_verification),
            "anchor_count": expected_tstringlist_comma,
            "verified_name_count": tstringlist_comma_verification["verified_name_count"],
            "reopen_failure_count": tstringlist_comma_verification["failure_count"],
        }
    if tstringlist_comma is not None:
        result["tstringlist_comma_anchors"] = tstringlist_comma
        result["interpretation"].append(
            "The ninety-fifth database revision also contains the separately reviewed TStringList comma parser, constructor, and serializer anchors."
        )
    tstringlist_extended = None
    if args.tstringlist_extended_anchors or args.tstringlist_extended_verification:
        if not args.tstringlist_extended_anchors or not args.tstringlist_extended_verification:
            raise ValueError(
                "extended TStringList anchors and extended TStringList verification must be supplied together"
            )
        tstringlist_extended_document = load(args.tstringlist_extended_anchors)
        tstringlist_extended_verification = load(args.tstringlist_extended_verification)
        if tstringlist_extended_document.get("artifact") != "spectron_tstringlist_extended_manual_translation_anchors_20260826":
            raise ValueError("unexpected extended TStringList anchor artifact")
        if not tstringlist_extended_verification.get("verified"):
            raise ValueError("extended TStringList anchor reopen verification did not pass")
        expected_tstringlist_extended = len(tstringlist_extended_document["anchors"])
        if tstringlist_extended_verification["verified_name_count"] != expected_tstringlist_extended:
            raise ValueError("extended TStringList verification count differs from artifact")
        tstringlist_extended = {
            "anchor_path": str(args.tstringlist_extended_anchors),
            "anchor_sha256": sha256_path(args.tstringlist_extended_anchors),
            "reopen_verification": str(args.tstringlist_extended_verification),
            "anchor_count": expected_tstringlist_extended,
            "verified_name_count": tstringlist_extended_verification["verified_name_count"],
            "reopen_failure_count": tstringlist_extended_verification["failure_count"],
        }
    if tstringlist_extended is not None:
        result["tstringlist_extended_anchors"] = tstringlist_extended
        result["interpretation"].append(
            "The ninety-sixth database revision also contains the separately reviewed TStringList assignment, key/value, serialization, file-output, and tokenizer anchors."
        )
    hash_family = None
    if args.hash_family_anchors or args.hash_family_verification:
        if not args.hash_family_anchors or not args.hash_family_verification:
            raise ValueError(
                "hash-family anchors and hash-family verification must be supplied together"
            )
        hash_family_document = load(args.hash_family_anchors)
        hash_family_verification = load(args.hash_family_verification)
        if hash_family_document.get("artifact") != "spectron_hash_family_manual_translation_anchors_20260826":
            raise ValueError("unexpected hash-family anchor artifact")
        if not hash_family_verification.get("verified"):
            raise ValueError("hash-family anchor reopen verification did not pass")
        expected_hash_family = len(hash_family_document["anchors"])
        if hash_family_verification["verified_name_count"] != expected_hash_family:
            raise ValueError("hash-family verification count differs from artifact")
        hash_family = {
            "anchor_path": str(args.hash_family_anchors),
            "anchor_sha256": sha256_path(args.hash_family_anchors),
            "reopen_verification": str(args.hash_family_verification),
            "anchor_count": expected_hash_family,
            "verified_name_count": hash_family_verification["verified_name_count"],
            "reopen_failure_count": hash_family_verification["failure_count"],
        }
    if hash_family is not None:
        result["hash_family_anchors"] = hash_family
        result["interpretation"].append(
            "The ninety-seventh database revision also contains the separately reviewed THashList lookup, assignment, sorting, and THashStrings value and serialization anchors."
        )
    options = None
    if args.options_anchors or args.options_verification:
        if not args.options_anchors or not args.options_verification:
            raise ValueError(
                "options anchors and options verification must be supplied together"
            )
        options_document = load(args.options_anchors)
        options_verification = load(args.options_verification)
        if options_document.get("artifact") != "spectron_options_manual_translation_anchors_20260826":
            raise ValueError("unexpected options anchor artifact")
        if not options_verification.get("verified"):
            raise ValueError("options anchor reopen verification did not pass")
        expected_options = len(options_document["anchors"])
        if options_verification["verified_name_count"] != expected_options:
            raise ValueError("options verification count differs from artifact")
        options = {
            "anchor_path": str(args.options_anchors),
            "anchor_sha256": sha256_path(args.options_anchors),
            "reopen_verification": str(args.options_verification),
            "anchor_count": expected_options,
            "verified_name_count": options_verification["verified_name_count"],
            "reopen_failure_count": options_verification["failure_count"],
        }
    if options is not None:
        result["options_anchors"] = options
        result["interpretation"].append(
            "The ninety-eighth database revision also contains the separately reviewed TOptions GUI-style setter, decoded credential getter, account persistence, and timer-refresh anchors."
        )
    texture = None
    if args.texture_anchors or args.texture_verification:
        if not args.texture_anchors or not args.texture_verification:
            raise ValueError(
                "texture anchors and texture verification must be supplied together"
            )
        texture_document = load(args.texture_anchors)
        texture_verification = load(args.texture_verification)
        if texture_document.get("artifact") != "spectron_texture_manual_translation_anchors_20260826":
            raise ValueError("unexpected texture anchor artifact")
        if not texture_verification.get("verified"):
            raise ValueError("texture anchor reopen verification did not pass")
        expected_texture = len(texture_document["anchors"])
        if texture_verification["verified_name_count"] != expected_texture:
            raise ValueError("texture verification count differs from artifact")
        texture = {
            "anchor_path": str(args.texture_anchors),
            "anchor_sha256": sha256_path(args.texture_anchors),
            "reopen_verification": str(args.texture_verification),
            "anchor_count": expected_texture,
            "verified_name_count": texture_verification["verified_name_count"],
            "reopen_failure_count": texture_verification["failure_count"],
        }
    if texture is not None:
        result["texture_anchors"] = texture
        result["interpretation"].append(
            "The ninety-ninth database revision also contains the separately reviewed TTexture bitmap access, GPU texture lifecycle, Graal lookup, and static registry anchors."
        )
    drawing_panel_texture = None
    if args.drawing_panel_texture_anchors or args.drawing_panel_texture_verification:
        if not args.drawing_panel_texture_anchors or not args.drawing_panel_texture_verification:
            raise ValueError(
                "drawing-panel texture anchors and drawing-panel texture verification must be supplied together"
            )
        drawing_panel_texture_document = load(args.drawing_panel_texture_anchors)
        drawing_panel_texture_verification = load(args.drawing_panel_texture_verification)
        if drawing_panel_texture_document.get("artifact") != "spectron_drawing_panel_texture_manual_translation_anchors_20260826":
            raise ValueError("unexpected drawing-panel texture anchor artifact")
        if not drawing_panel_texture_verification.get("verified"):
            raise ValueError("drawing-panel texture anchor reopen verification did not pass")
        expected_drawing_panel_texture = len(drawing_panel_texture_document["anchors"])
        if drawing_panel_texture_verification["verified_name_count"] != expected_drawing_panel_texture:
            raise ValueError("drawing-panel texture verification count differs from artifact")
        drawing_panel_texture = {
            "anchor_path": str(args.drawing_panel_texture_anchors),
            "anchor_sha256": sha256_path(args.drawing_panel_texture_anchors),
            "reopen_verification": str(args.drawing_panel_texture_verification),
            "anchor_count": expected_drawing_panel_texture,
            "verified_name_count": drawing_panel_texture_verification["verified_name_count"],
            "reopen_failure_count": drawing_panel_texture_verification["failure_count"],
        }
    if drawing_panel_texture is not None:
        result["drawing_panel_texture_anchors"] = drawing_panel_texture
        result["interpretation"].append(
            "The one-hundredth database revision also contains the separately reviewed TDrawingPanelTexture destructor, constructor, and texture-dimension anchors."
        )
    draw_texture = None
    if args.draw_texture_anchors or args.draw_texture_verification:
        if not args.draw_texture_anchors or not args.draw_texture_verification:
            raise ValueError(
                "draw-texture anchors and draw-texture verification must be supplied together"
            )
        draw_texture_document = load(args.draw_texture_anchors)
        draw_texture_verification = load(args.draw_texture_verification)
        if draw_texture_document.get("artifact") != "spectron_draw_texture_manual_translation_anchors_20260826":
            raise ValueError("unexpected draw-texture anchor artifact")
        if not draw_texture_verification.get("verified"):
            raise ValueError("draw-texture anchor reopen verification did not pass")
        expected_draw_texture = len(draw_texture_document["anchors"])
        if draw_texture_verification["verified_name_count"] != expected_draw_texture:
            raise ValueError("draw-texture verification count differs from artifact")
        draw_texture = {
            "anchor_path": str(args.draw_texture_anchors),
            "anchor_sha256": sha256_path(args.draw_texture_anchors),
            "reopen_verification": str(args.draw_texture_verification),
            "anchor_count": expected_draw_texture,
            "verified_name_count": draw_texture_verification["verified_name_count"],
            "reopen_failure_count": draw_texture_verification["failure_count"],
        }
    if draw_texture is not None:
        result["draw_texture_anchors"] = draw_texture
        result["interpretation"].append(
            "The one-hundred-first database revision also contains the separately reviewed TDrawTexture static initializer, registry cleanup, reload, and bind anchors."
        )
    bitmap_array_holder = None
    if args.bitmap_array_holder_anchors or args.bitmap_array_holder_verification:
        if not args.bitmap_array_holder_anchors or not args.bitmap_array_holder_verification:
            raise ValueError(
                "bitmap-array holder anchors and bitmap-array holder verification must be supplied together"
            )
        bitmap_array_holder_document = load(args.bitmap_array_holder_anchors)
        bitmap_array_holder_verification = load(args.bitmap_array_holder_verification)
        if bitmap_array_holder_document.get("artifact") != "spectron_bitmap_array_holder_manual_translation_anchors_20260826":
            raise ValueError("unexpected bitmap-array holder anchor artifact")
        if not bitmap_array_holder_verification.get("verified"):
            raise ValueError("bitmap-array holder anchor reopen verification did not pass")
        expected_bitmap_array_holder = len(bitmap_array_holder_document["anchors"])
        if bitmap_array_holder_verification["verified_name_count"] != expected_bitmap_array_holder:
            raise ValueError("bitmap-array holder verification count differs from artifact")
        bitmap_array_holder = {
            "anchor_path": str(args.bitmap_array_holder_anchors),
            "anchor_sha256": sha256_path(args.bitmap_array_holder_anchors),
            "reopen_verification": str(args.bitmap_array_holder_verification),
            "anchor_count": expected_bitmap_array_holder,
            "verified_name_count": bitmap_array_holder_verification["verified_name_count"],
            "reopen_failure_count": bitmap_array_holder_verification["failure_count"],
        }
    if bitmap_array_holder is not None:
        result["bitmap_array_holder_anchors"] = bitmap_array_holder
        result["interpretation"].append(
            "The one-hundred-second database revision also contains the separately reviewed TBitmapArrayHolder constructor, rectangle discovery, lookup, and registry anchors."
        )
    color_manager = None
    if args.color_manager_anchors or args.color_manager_verification:
        if not args.color_manager_anchors or not args.color_manager_verification:
            raise ValueError(
                "color-manager anchors and color-manager verification must be supplied together"
            )
        color_manager_document = load(args.color_manager_anchors)
        color_manager_verification = load(args.color_manager_verification)
        if color_manager_document.get("artifact") != "spectron_color_manager_manual_translation_anchors_20260826":
            raise ValueError("unexpected color-manager anchor artifact")
        if not color_manager_verification.get("verified"):
            raise ValueError("color-manager anchor reopen verification did not pass")
        expected_color_manager = len(color_manager_document["anchors"])
        if color_manager_verification["verified_name_count"] != expected_color_manager:
            raise ValueError("color-manager verification count differs from artifact")
        color_manager = {
            "anchor_path": str(args.color_manager_anchors),
            "anchor_sha256": sha256_path(args.color_manager_anchors),
            "reopen_verification": str(args.color_manager_verification),
            "anchor_count": expected_color_manager,
            "verified_name_count": color_manager_verification["verified_name_count"],
            "reopen_failure_count": color_manager_verification["failure_count"],
        }
    if color_manager is not None:
        result["color_manager_anchors"] = color_manager
        result["interpretation"].append(
            "The one-hundred-third database revision also contains the separately reviewed TColorManager activation, stack-state, cleanup, pop, and initialization anchors."
        )
    font_runtime = None
    if args.font_runtime_anchors or args.font_runtime_verification:
        if not args.font_runtime_anchors or not args.font_runtime_verification:
            raise ValueError(
                "font-runtime anchors and font-runtime verification must be supplied together"
            )
        font_runtime_document = load(args.font_runtime_anchors)
        font_runtime_verification = load(args.font_runtime_verification)
        if font_runtime_document.get("artifact") != "spectron_font_runtime_manual_translation_anchors_20260826":
            raise ValueError("unexpected font-runtime anchor artifact")
        if not font_runtime_verification.get("verified"):
            raise ValueError("font-runtime anchor reopen verification did not pass")
        expected_font_runtime = len(font_runtime_document["anchors"])
        if font_runtime_verification["verified_name_count"] != expected_font_runtime:
            raise ValueError("font-runtime verification count differs from artifact")
        font_runtime = {
            "anchor_path": str(args.font_runtime_anchors),
            "anchor_sha256": sha256_path(args.font_runtime_anchors),
            "reopen_verification": str(args.font_runtime_verification),
            "anchor_count": expected_font_runtime,
            "verified_name_count": font_runtime_verification["verified_name_count"],
            "reopen_failure_count": font_runtime_verification["failure_count"],
        }
    if font_runtime is not None:
        result["font_runtime_anchors"] = font_runtime
        result["interpretation"].append(
            "The one-hundred-fourth database revision also contains the separately reviewed TFont, TFontManager, TFontOptions, and TFontData residual anchors."
        )
    window_input = None
    if args.window_input_anchors or args.window_input_verification:
        if not args.window_input_anchors or not args.window_input_verification:
            raise ValueError(
                "window-input anchors and window-input verification must be supplied together"
            )
        window_input_document = load(args.window_input_anchors)
        window_input_verification = load(args.window_input_verification)
        if window_input_document.get("artifact") != "spectron_window_input_manual_translation_anchors_20260826":
            raise ValueError("unexpected window-input anchor artifact")
        if not window_input_verification.get("verified"):
            raise ValueError("window-input anchor reopen verification did not pass")
        expected_window_input = len(window_input_document["anchors"])
        if window_input_verification["verified_name_count"] != expected_window_input:
            raise ValueError("window-input verification count differs from artifact")
        window_input = {
            "anchor_path": str(args.window_input_anchors),
            "anchor_sha256": sha256_path(args.window_input_anchors),
            "reopen_verification": str(args.window_input_verification),
            "anchor_count": expected_window_input,
            "verified_name_count": window_input_verification["verified_name_count"],
            "reopen_failure_count": window_input_verification["failure_count"],
        }
    if window_input is not None:
        result["window_input_anchors"] = window_input
        result["interpretation"].append(
            "The one-hundred-fifth database revision also contains the separately reviewed TWindow mouse and key event dispatch anchors."
        )
    drawing_panel_residual = None
    if args.drawing_panel_residual_anchors or args.drawing_panel_residual_verification:
        if not args.drawing_panel_residual_anchors or not args.drawing_panel_residual_verification:
            raise ValueError(
                "drawing-panel residual anchors and drawing-panel residual verification must be supplied together"
            )
        drawing_panel_residual_document = load(args.drawing_panel_residual_anchors)
        drawing_panel_residual_verification = load(args.drawing_panel_residual_verification)
        if drawing_panel_residual_document.get("artifact") != "spectron_drawing_panel_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected drawing-panel residual anchor artifact")
        if not drawing_panel_residual_verification.get("verified"):
            raise ValueError("drawing-panel residual anchor reopen verification did not pass")
        expected_drawing_panel_residual = len(drawing_panel_residual_document["anchors"])
        if drawing_panel_residual_verification["verified_name_count"] != expected_drawing_panel_residual:
            raise ValueError("drawing-panel residual verification count differs from artifact")
        drawing_panel_residual = {
            "anchor_path": str(args.drawing_panel_residual_anchors),
            "anchor_sha256": sha256_path(args.drawing_panel_residual_anchors),
            "reopen_verification": str(args.drawing_panel_residual_verification),
            "anchor_count": expected_drawing_panel_residual,
            "verified_name_count": drawing_panel_residual_verification["verified_name_count"],
            "reopen_failure_count": drawing_panel_residual_verification["failure_count"],
        }
    if drawing_panel_residual is not None:
        result["drawing_panel_residual_anchors"] = drawing_panel_residual
        result["interpretation"].append(
            "The one-hundred-sixth database revision also contains the separately reviewed TDrawingPanel residual constructor, image, filter, and palette anchors."
        )
    image_html = None
    if args.image_html_anchors or args.image_html_verification:
        if not args.image_html_anchors or not args.image_html_verification:
            raise ValueError(
                "image/html anchors and image/html verification must be supplied together"
            )
        image_html_document = load(args.image_html_anchors)
        image_html_verification = load(args.image_html_verification)
        if image_html_document.get("artifact") != "spectron_image_html_manual_translation_anchors_20260826":
            raise ValueError("unexpected image/html anchor artifact")
        if not image_html_verification.get("verified"):
            raise ValueError("image/html anchor reopen verification did not pass")
        expected_image_html = len(image_html_document["anchors"])
        if image_html_verification["verified_name_count"] != expected_image_html:
            raise ValueError("image/html verification count differs from artifact")
        image_html = {
            "anchor_path": str(args.image_html_anchors),
            "anchor_sha256": sha256_path(args.image_html_anchors),
            "reopen_verification": str(args.image_html_verification),
            "anchor_count": expected_image_html,
            "verified_name_count": image_html_verification["verified_name_count"],
            "reopen_failure_count": image_html_verification["failure_count"],
        }
    if image_html is not None:
        result["image_html_anchors"] = image_html
        result["interpretation"].append(
            "The one-hundred-seventh database revision also contains the separately reviewed HTML color registry and image-animation lifecycle anchors."
        )
    panel_bitmap = None
    if args.panel_bitmap_anchors or args.panel_bitmap_verification:
        if not args.panel_bitmap_anchors or not args.panel_bitmap_verification:
            raise ValueError(
                "panel/bitmap anchors and panel/bitmap verification must be supplied together"
            )
        panel_bitmap_document = load(args.panel_bitmap_anchors)
        panel_bitmap_verification = load(args.panel_bitmap_verification)
        if panel_bitmap_document.get("artifact") != "spectron_panel_bitmap_manual_translation_anchors_20260826":
            raise ValueError("unexpected panel/bitmap anchor artifact")
        if not panel_bitmap_verification.get("verified"):
            raise ValueError("panel/bitmap anchor reopen verification did not pass")
        expected_panel_bitmap = len(panel_bitmap_document["anchors"])
        if panel_bitmap_verification["verified_name_count"] != expected_panel_bitmap:
            raise ValueError("panel/bitmap verification count differs from artifact")
        panel_bitmap = {
            "anchor_path": str(args.panel_bitmap_anchors),
            "anchor_sha256": sha256_path(args.panel_bitmap_anchors),
            "reopen_verification": str(args.panel_bitmap_verification),
            "anchor_count": expected_panel_bitmap,
            "verified_name_count": panel_bitmap_verification["verified_name_count"],
            "reopen_failure_count": panel_bitmap_verification["failure_count"],
        }
    if panel_bitmap is not None:
        result["panel_bitmap_anchors"] = panel_bitmap
        result["interpretation"].append(
            "The one-hundred-eighth database revision also contains the separately reviewed panel-interface construction and bitmap-loader dispatch, lookup, and redownload anchors."
        )
    gif_decoder = None
    if args.gif_decoder_anchors or args.gif_decoder_verification:
        if not args.gif_decoder_anchors or not args.gif_decoder_verification:
            raise ValueError(
                "GIF decoder anchors and GIF decoder verification must be supplied together"
            )
        gif_decoder_document = load(args.gif_decoder_anchors)
        gif_decoder_verification = load(args.gif_decoder_verification)
        if gif_decoder_document.get("artifact") != "spectron_gif_decoder_manual_translation_anchor_20260826":
            raise ValueError("unexpected GIF decoder anchor artifact")
        if not gif_decoder_verification.get("verified"):
            raise ValueError("GIF decoder anchor reopen verification did not pass")
        expected_gif_decoder = len(gif_decoder_document["anchors"])
        if gif_decoder_verification["verified_name_count"] != expected_gif_decoder:
            raise ValueError("GIF decoder verification count differs from artifact")
        gif_decoder = {
            "anchor_path": str(args.gif_decoder_anchors),
            "anchor_sha256": sha256_path(args.gif_decoder_anchors),
            "reopen_verification": str(args.gif_decoder_verification),
            "anchor_count": expected_gif_decoder,
            "verified_name_count": gif_decoder_verification["verified_name_count"],
            "reopen_failure_count": gif_decoder_verification["failure_count"],
        }
    if gif_decoder is not None:
        result["gif_decoder_anchors"] = gif_decoder
        result["interpretation"].append(
            "The one-hundred-ninth database revision also contains the separately reviewed GIF stream decoder and animation-step construction anchor."
        )
    window_residual = None
    if args.window_residual_anchors or args.window_residual_verification:
        if not args.window_residual_anchors or not args.window_residual_verification:
            raise ValueError(
                "window residual anchors and window residual verification must be supplied together"
            )
        window_residual_document = load(args.window_residual_anchors)
        window_residual_verification = load(args.window_residual_verification)
        if window_residual_document.get("artifact") != "spectron_window_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected window residual anchor artifact")
        if not window_residual_verification.get("verified"):
            raise ValueError("window residual anchor reopen verification did not pass")
        expected_window_residual = len(window_residual_document["anchors"])
        if window_residual_verification["verified_name_count"] != expected_window_residual:
            raise ValueError("window residual verification count differs from artifact")
        window_residual = {
            "anchor_path": str(args.window_residual_anchors),
            "anchor_sha256": sha256_path(args.window_residual_anchors),
            "reopen_verification": str(args.window_residual_verification),
            "anchor_count": expected_window_residual,
            "verified_name_count": window_residual_verification["verified_name_count"],
            "reopen_failure_count": window_residual_verification["failure_count"],
        }
    if window_residual is not None:
        result["window_residual_anchors"] = window_residual
        result["interpretation"].append(
            "The one-hundred-tenth database revision also contains the separately reviewed TWindow close-query and pixel-buffer factory anchors."
        )
    sound_runtime = None
    if args.sound_runtime_anchors or args.sound_runtime_verification:
        if not args.sound_runtime_anchors or not args.sound_runtime_verification:
            raise ValueError(
                "sound-runtime anchors and sound-runtime verification must be supplied together"
            )
        sound_runtime_document = load(args.sound_runtime_anchors)
        sound_runtime_verification = load(args.sound_runtime_verification)
        if sound_runtime_document.get("artifact") != "spectron_sound_runtime_manual_translation_anchors_20260826":
            raise ValueError("unexpected sound-runtime anchor artifact")
        if not sound_runtime_verification.get("verified"):
            raise ValueError("sound-runtime anchor reopen verification did not pass")
        expected_sound_runtime = len(sound_runtime_document["anchors"])
        if sound_runtime_verification["verified_name_count"] != expected_sound_runtime:
            raise ValueError("sound-runtime verification count differs from artifact")
        sound_runtime = {
            "anchor_path": str(args.sound_runtime_anchors),
            "anchor_sha256": sha256_path(args.sound_runtime_anchors),
            "reopen_verification": str(args.sound_runtime_verification),
            "anchor_count": expected_sound_runtime,
            "verified_name_count": sound_runtime_verification["verified_name_count"],
            "reopen_failure_count": sound_runtime_verification["failure_count"],
        }
    if sound_runtime is not None:
        result["sound_runtime_anchors"] = sound_runtime
        result["interpretation"].append(
            "The one-hundred-eleventh database revision also contains the separately reviewed sound-manager dispatch, note-pitch, and Java playback anchors."
        )
    pixelbuffer_residual = None
    if args.pixelbuffer_residual_anchors or args.pixelbuffer_residual_verification:
        if not args.pixelbuffer_residual_anchors or not args.pixelbuffer_residual_verification:
            raise ValueError(
                "pixelbuffer residual anchors and pixelbuffer residual verification must be supplied together"
            )
        pixelbuffer_residual_document = load(args.pixelbuffer_residual_anchors)
        pixelbuffer_residual_verification = load(args.pixelbuffer_residual_verification)
        if pixelbuffer_residual_document.get("artifact") != "spectron_pixelbuffer_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected pixelbuffer residual anchor artifact")
        if not pixelbuffer_residual_verification.get("verified"):
            raise ValueError("pixelbuffer residual anchor reopen verification did not pass")
        expected_pixelbuffer_residual = len(pixelbuffer_residual_document["anchors"])
        if pixelbuffer_residual_verification["verified_name_count"] != expected_pixelbuffer_residual:
            raise ValueError("pixelbuffer residual verification count differs from artifact")
        pixelbuffer_residual = {
            "anchor_path": str(args.pixelbuffer_residual_anchors),
            "anchor_sha256": sha256_path(args.pixelbuffer_residual_anchors),
            "reopen_verification": str(args.pixelbuffer_residual_verification),
            "anchor_count": expected_pixelbuffer_residual,
            "verified_name_count": pixelbuffer_residual_verification["verified_name_count"],
            "reopen_failure_count": pixelbuffer_residual_verification["failure_count"],
        }
    if pixelbuffer_residual is not None:
        result["pixelbuffer_residual_anchors"] = pixelbuffer_residual
        result["interpretation"].append(
            "The one-hundred-twelfth database revision also contains the separately reviewed TPixelBuffer field, allocation, and base texture-hook anchors."
        )
    pixelbuffer_bitmap_lifecycle = None
    if args.pixelbuffer_bitmap_lifecycle_anchors or args.pixelbuffer_bitmap_lifecycle_verification:
        if not args.pixelbuffer_bitmap_lifecycle_anchors or not args.pixelbuffer_bitmap_lifecycle_verification:
            raise ValueError(
                "pixelbuffer bitmap-lifecycle anchors and pixelbuffer bitmap-lifecycle verification must be supplied together"
            )
        pixelbuffer_bitmap_lifecycle_document = load(args.pixelbuffer_bitmap_lifecycle_anchors)
        pixelbuffer_bitmap_lifecycle_verification = load(args.pixelbuffer_bitmap_lifecycle_verification)
        if pixelbuffer_bitmap_lifecycle_document.get("artifact") != "spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826":
            raise ValueError("unexpected pixelbuffer bitmap-lifecycle anchor artifact")
        if not pixelbuffer_bitmap_lifecycle_verification.get("verified"):
            raise ValueError("pixelbuffer bitmap-lifecycle anchor reopen verification did not pass")
        expected_pixelbuffer_bitmap_lifecycle = len(pixelbuffer_bitmap_lifecycle_document["anchors"])
        if pixelbuffer_bitmap_lifecycle_verification["verified_name_count"] != expected_pixelbuffer_bitmap_lifecycle:
            raise ValueError("pixelbuffer bitmap-lifecycle verification count differs from artifact")
        pixelbuffer_bitmap_lifecycle = {
            "anchor_path": str(args.pixelbuffer_bitmap_lifecycle_anchors),
            "anchor_sha256": sha256_path(args.pixelbuffer_bitmap_lifecycle_anchors),
            "reopen_verification": str(args.pixelbuffer_bitmap_lifecycle_verification),
            "anchor_count": expected_pixelbuffer_bitmap_lifecycle,
            "verified_name_count": pixelbuffer_bitmap_lifecycle_verification["verified_name_count"],
            "reopen_failure_count": pixelbuffer_bitmap_lifecycle_verification["failure_count"],
        }
    if pixelbuffer_bitmap_lifecycle is not None:
        result["pixelbuffer_bitmap_lifecycle_anchors"] = pixelbuffer_bitmap_lifecycle
        result["interpretation"].append(
            "The one-hundred-thirteenth database revision also contains the separately reviewed TPixelBuffer and TBitmap destructor pairs that correct the earlier medium-confidence class collision."
        )
    animation_palette_residual = None
    if args.animation_palette_residual_anchors or args.animation_palette_residual_verification:
        if not args.animation_palette_residual_anchors or not args.animation_palette_residual_verification:
            raise ValueError(
                "animation-palette residual anchors and animation-palette residual verification must be supplied together"
            )
        animation_palette_residual_document = load(args.animation_palette_residual_anchors)
        animation_palette_residual_verification = load(args.animation_palette_residual_verification)
        if animation_palette_residual_document.get("artifact") != "spectron_animation_palette_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected animation-palette residual anchor artifact")
        if not animation_palette_residual_verification.get("verified"):
            raise ValueError("animation-palette residual anchor reopen verification did not pass")
        expected_animation_palette_residual = len(animation_palette_residual_document["anchors"])
        if animation_palette_residual_verification["verified_name_count"] != expected_animation_palette_residual:
            raise ValueError("animation-palette residual verification count differs from artifact")
        animation_palette_residual = {
            "anchor_path": str(args.animation_palette_residual_anchors),
            "anchor_sha256": sha256_path(args.animation_palette_residual_anchors),
            "reopen_verification": str(args.animation_palette_residual_verification),
            "anchor_count": expected_animation_palette_residual,
            "verified_name_count": animation_palette_residual_verification["verified_name_count"],
            "reopen_failure_count": animation_palette_residual_verification["failure_count"],
        }
    if animation_palette_residual is not None:
        result["animation_palette_residual_anchors"] = animation_palette_residual
        result["interpretation"].append(
            "The one-hundred-fourteenth database revision also contains the separately reviewed image-animation base hooks and MNG or palette deleting-destructor anchors."
        )
    panel_virtual_renderer_residual = None
    if args.panel_virtual_renderer_residual_anchors or args.panel_virtual_renderer_residual_verification:
        if not args.panel_virtual_renderer_residual_anchors or not args.panel_virtual_renderer_residual_verification:
            raise ValueError(
                "panel virtual renderer residual anchors and panel virtual renderer residual verification must be supplied together"
            )
        panel_virtual_renderer_residual_document = load(args.panel_virtual_renderer_residual_anchors)
        panel_virtual_renderer_residual_verification = load(args.panel_virtual_renderer_residual_verification)
        if panel_virtual_renderer_residual_document.get("artifact") != "spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected panel virtual renderer residual anchor artifact")
        if not panel_virtual_renderer_residual_verification.get("verified"):
            raise ValueError("panel virtual renderer residual anchor reopen verification did not pass")
        expected_panel_virtual_renderer_residual = len(panel_virtual_renderer_residual_document["anchors"])
        if panel_virtual_renderer_residual_verification["verified_name_count"] != expected_panel_virtual_renderer_residual:
            raise ValueError("panel virtual renderer residual verification count differs from artifact")
        panel_virtual_renderer_residual = {
            "anchor_path": str(args.panel_virtual_renderer_residual_anchors),
            "anchor_sha256": sha256_path(args.panel_virtual_renderer_residual_anchors),
            "reopen_verification": str(args.panel_virtual_renderer_residual_verification),
            "anchor_count": expected_panel_virtual_renderer_residual,
            "verified_name_count": panel_virtual_renderer_residual_verification["verified_name_count"],
            "reopen_failure_count": panel_virtual_renderer_residual_verification["failure_count"],
        }
    if panel_virtual_renderer_residual is not None:
        result["panel_virtual_renderer_residual_anchors"] = panel_virtual_renderer_residual
        result["interpretation"].append(
            "The one-hundred-seventeenth database revision also contains the separately reviewed panel-interface virtual hooks, panel-port tail hooks, and graphic-operation texture flush loop."
        )
    dummy_panel_residual = None
    if args.dummy_panel_residual_anchors or args.dummy_panel_residual_verification:
        if not args.dummy_panel_residual_anchors or not args.dummy_panel_residual_verification:
            raise ValueError(
                "dummy-panel residual anchors and dummy-panel residual verification must be supplied together"
            )
        dummy_panel_residual_document = load(args.dummy_panel_residual_anchors)
        dummy_panel_residual_verification = load(args.dummy_panel_residual_verification)
        if dummy_panel_residual_document.get("artifact") != "spectron_dummy_panel_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected dummy-panel residual anchor artifact")
        if not dummy_panel_residual_verification.get("verified"):
            raise ValueError("dummy-panel residual anchor reopen verification did not pass")
        expected_dummy_panel_residual = len(dummy_panel_residual_document["anchors"])
        if dummy_panel_residual_verification["verified_name_count"] != expected_dummy_panel_residual:
            raise ValueError("dummy-panel residual verification count differs from artifact")
        dummy_panel_residual = {
            "anchor_path": str(args.dummy_panel_residual_anchors),
            "anchor_sha256": sha256_path(args.dummy_panel_residual_anchors),
            "reopen_verification": str(args.dummy_panel_residual_verification),
            "anchor_count": expected_dummy_panel_residual,
            "verified_name_count": dummy_panel_residual_verification["verified_name_count"],
            "reopen_failure_count": dummy_panel_residual_verification["failure_count"],
        }
    if dummy_panel_residual is not None:
        result["dummy_panel_residual_anchors"] = dummy_panel_residual
        result["interpretation"].append(
            "The one-hundred-eighteenth database revision also contains the separately reviewed residual TPanelInterface hooks and TDummyPanel virtual and lifecycle block."
        )
    screen_panel_renderer_residual = None
    if args.screen_panel_renderer_residual_anchors or args.screen_panel_renderer_residual_verification:
        if not args.screen_panel_renderer_residual_anchors or not args.screen_panel_renderer_residual_verification:
            raise ValueError(
                "screen-panel renderer residual anchors and screen-panel renderer residual verification must be supplied together"
            )
        screen_panel_renderer_residual_document = load(args.screen_panel_renderer_residual_anchors)
        screen_panel_renderer_residual_verification = load(args.screen_panel_renderer_residual_verification)
        if screen_panel_renderer_residual_document.get("artifact") != "spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected screen-panel renderer residual anchor artifact")
        if not screen_panel_renderer_residual_verification.get("verified"):
            raise ValueError("screen-panel renderer residual anchor reopen verification did not pass")
        expected_screen_panel_renderer_residual = len(screen_panel_renderer_residual_document["anchors"])
        if screen_panel_renderer_residual_verification["verified_name_count"] != expected_screen_panel_renderer_residual:
            raise ValueError("screen-panel renderer residual verification count differs from artifact")
        screen_panel_renderer_residual = {
            "anchor_path": str(args.screen_panel_renderer_residual_anchors),
            "anchor_sha256": sha256_path(args.screen_panel_renderer_residual_anchors),
            "reopen_verification": str(args.screen_panel_renderer_residual_verification),
            "anchor_count": expected_screen_panel_renderer_residual,
            "verified_name_count": screen_panel_renderer_residual_verification["verified_name_count"],
            "reopen_failure_count": screen_panel_renderer_residual_verification["failure_count"],
        }
    if screen_panel_renderer_residual is not None:
        result["screen_panel_renderer_residual_anchors"] = screen_panel_renderer_residual
        result["interpretation"].append(
            "The one-hundred-nineteenth database revision also contains the separately reviewed residual pixel-buffer texture predicate and concrete screen-panel matrix, shader, triangle-strip, and alpha-reference methods."
        )
    screen_panel_window_gles_residual = None
    if args.screen_panel_window_gles_residual_anchors or args.screen_panel_window_gles_residual_verification:
        if not args.screen_panel_window_gles_residual_anchors or not args.screen_panel_window_gles_residual_verification:
            raise ValueError(
                "screen-panel window GLES residual anchors and screen-panel window GLES residual verification must be supplied together"
            )
        screen_panel_window_gles_residual_document = load(args.screen_panel_window_gles_residual_anchors)
        screen_panel_window_gles_residual_verification = load(args.screen_panel_window_gles_residual_verification)
        if screen_panel_window_gles_residual_document.get("artifact") != "spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected screen-panel window GLES residual anchor artifact")
        if not screen_panel_window_gles_residual_verification.get("verified"):
            raise ValueError("screen-panel window GLES residual anchor reopen verification did not pass")
        expected_screen_panel_window_gles_residual = len(screen_panel_window_gles_residual_document["anchors"])
        if screen_panel_window_gles_residual_verification["verified_name_count"] != expected_screen_panel_window_gles_residual:
            raise ValueError("screen-panel window GLES residual verification count differs from artifact")
        screen_panel_window_gles_residual = {
            "anchor_path": str(args.screen_panel_window_gles_residual_anchors),
            "anchor_sha256": sha256_path(args.screen_panel_window_gles_residual_anchors),
            "reopen_verification": str(args.screen_panel_window_gles_residual_verification),
            "anchor_count": expected_screen_panel_window_gles_residual,
            "verified_name_count": screen_panel_window_gles_residual_verification["verified_name_count"],
            "reopen_failure_count": screen_panel_window_gles_residual_verification["failure_count"],
        }
    if screen_panel_window_gles_residual is not None:
        result["screen_panel_window_gles_residual_anchors"] = screen_panel_window_gles_residual
        result["interpretation"].append(
            "The one-hundred-twentieth database revision also contains the separately reviewed screen-panel polygon-font stub and TWindowGLES lifecycle, pixel-buffer factory, destructor, and native-mode anchors."
        )
    font_manager_font_residual = None
    if args.font_manager_font_residual_anchors or args.font_manager_font_residual_verification:
        if not args.font_manager_font_residual_anchors or not args.font_manager_font_residual_verification:
            raise ValueError(
                "font-manager font residual anchors and font-manager font residual verification must be supplied together"
            )
        font_manager_font_residual_document = load(args.font_manager_font_residual_anchors)
        font_manager_font_residual_verification = load(args.font_manager_font_residual_verification)
        if font_manager_font_residual_document.get("artifact") != "spectron_font_manager_font_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected font-manager font residual anchor artifact")
        if not font_manager_font_residual_verification.get("verified"):
            raise ValueError("font-manager font residual anchor reopen verification did not pass")
        expected_font_manager_font_residual = len(font_manager_font_residual_document["anchors"])
        if font_manager_font_residual_verification["verified_name_count"] != expected_font_manager_font_residual:
            raise ValueError("font-manager font residual verification count differs from artifact")
        font_manager_font_residual = {
            "anchor_path": str(args.font_manager_font_residual_anchors),
            "anchor_sha256": sha256_path(args.font_manager_font_residual_anchors),
            "reopen_verification": str(args.font_manager_font_residual_verification),
            "anchor_count": expected_font_manager_font_residual,
            "verified_name_count": font_manager_font_residual_verification["verified_name_count"],
            "reopen_failure_count": font_manager_font_residual_verification["failure_count"],
        }
    if font_manager_font_residual is not None:
        result["font_manager_font_residual_anchors"] = font_manager_font_residual
        result["interpretation"].append(
            "The one-hundred-twenty-first database revision also contains the separately reviewed TFont, TFontCharInfo, and TFontManager residual destructor, texture, cache, and text metric anchors."
        )
    font_options_font_data_residual = None
    if args.font_options_font_data_residual_anchors or args.font_options_font_data_residual_verification:
        if not args.font_options_font_data_residual_anchors or not args.font_options_font_data_residual_verification:
            raise ValueError(
                "font-options font-data residual anchors and font-options font-data residual verification must be supplied together"
            )
        font_options_font_data_residual_document = load(args.font_options_font_data_residual_anchors)
        font_options_font_data_residual_verification = load(args.font_options_font_data_residual_verification)
        if font_options_font_data_residual_document.get("artifact") != "spectron_font_options_font_data_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected font-options font-data residual anchor artifact")
        if not font_options_font_data_residual_verification.get("verified"):
            raise ValueError("font-options font-data residual anchor reopen verification did not pass")
        expected_font_options_font_data_residual = len(font_options_font_data_residual_document["anchors"])
        if font_options_font_data_residual_verification["verified_name_count"] != expected_font_options_font_data_residual:
            raise ValueError("font-options font-data residual verification count differs from artifact")
        font_options_font_data_residual = {
            "anchor_path": str(args.font_options_font_data_residual_anchors),
            "anchor_sha256": sha256_path(args.font_options_font_data_residual_anchors),
            "reopen_verification": str(args.font_options_font_data_residual_verification),
            "anchor_count": expected_font_options_font_data_residual,
            "verified_name_count": font_options_font_data_residual_verification["verified_name_count"],
            "reopen_failure_count": font_options_font_data_residual_verification["failure_count"],
        }
    if font_options_font_data_residual is not None:
        result["font_options_font_data_residual_anchors"] = font_options_font_data_residual
        result["interpretation"].append(
            "The one-hundred-twenty-second database revision also contains the separately reviewed screen-panel lifecycle, TFontOptions property, TFontData lookup, and TWindowProperties destructor anchors."
        )
    gui_control_profile_accessor = None
    if args.gui_control_profile_accessor_anchors or args.gui_control_profile_accessor_verification:
        if not args.gui_control_profile_accessor_anchors or not args.gui_control_profile_accessor_verification:
            raise ValueError(
                "GUI control profile accessor anchors and GUI control profile accessor verification must be supplied together"
            )
        gui_control_profile_accessor_document = load(args.gui_control_profile_accessor_anchors)
        gui_control_profile_accessor_verification = load(args.gui_control_profile_accessor_verification)
        if gui_control_profile_accessor_document.get("artifact") != "spectron_gui_control_profile_accessor_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control profile accessor artifact")
        if not gui_control_profile_accessor_verification.get("verified"):
            raise ValueError("GUI control profile accessor reopen verification did not pass")
        expected_gui_control_profile_accessor = len(gui_control_profile_accessor_document["anchors"])
        if gui_control_profile_accessor_verification["verified_name_count"] != expected_gui_control_profile_accessor:
            raise ValueError("GUI control profile accessor verification count differs from artifact")
        gui_control_profile_accessor = {
            "anchor_path": str(args.gui_control_profile_accessor_anchors),
            "anchor_sha256": sha256_path(args.gui_control_profile_accessor_anchors),
            "reopen_verification": str(args.gui_control_profile_accessor_verification),
            "anchor_count": expected_gui_control_profile_accessor,
            "verified_name_count": gui_control_profile_accessor_verification["verified_name_count"],
            "reopen_failure_count": gui_control_profile_accessor_verification["failure_count"],
        }
    if gui_control_profile_accessor is not None:
        result["gui_control_profile_accessor_anchors"] = gui_control_profile_accessor
        result["interpretation"].append(
            "The one-hundred-twenty-third database revision also contains the separately reviewed GuiControlProfile accessor block and its explicit target-only coverage gaps."
        )
    gui_control_profile_destructor = None
    if args.gui_control_profile_destructor_anchors or args.gui_control_profile_destructor_verification:
        if not args.gui_control_profile_destructor_anchors or not args.gui_control_profile_destructor_verification:
            raise ValueError(
                "GUI control profile destructor anchors and GUI control profile destructor verification must be supplied together"
            )
        gui_control_profile_destructor_document = load(args.gui_control_profile_destructor_anchors)
        gui_control_profile_destructor_verification = load(args.gui_control_profile_destructor_verification)
        if gui_control_profile_destructor_document.get("artifact") != "spectron_gui_control_profile_destructor_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control profile destructor artifact")
        if not gui_control_profile_destructor_verification.get("verified"):
            raise ValueError("GUI control profile destructor reopen verification did not pass")
        expected_gui_control_profile_destructor = len(gui_control_profile_destructor_document["anchors"])
        if gui_control_profile_destructor_verification["verified_name_count"] != expected_gui_control_profile_destructor:
            raise ValueError("GUI control profile destructor verification count differs from artifact")
        gui_control_profile_destructor = {
            "anchor_path": str(args.gui_control_profile_destructor_anchors),
            "anchor_sha256": sha256_path(args.gui_control_profile_destructor_anchors),
            "reopen_verification": str(args.gui_control_profile_destructor_verification),
            "anchor_count": expected_gui_control_profile_destructor,
            "verified_name_count": gui_control_profile_destructor_verification["verified_name_count"],
            "reopen_failure_count": gui_control_profile_destructor_verification["failure_count"],
        }
    if gui_control_profile_destructor is not None:
        result["gui_control_profile_destructor_anchors"] = gui_control_profile_destructor
        result["interpretation"].append(
            "The one-hundred-twenty-fourth database revision also contains the separately reviewed GuiControlProfileProperties and GuiControlProfile destructor family."
        )
    gui_control_property_residual = None
    if args.gui_control_property_residual_anchors or args.gui_control_property_residual_verification:
        if not args.gui_control_property_residual_anchors or not args.gui_control_property_residual_verification:
            raise ValueError(
                "GUI control property residual anchors and GUI control property residual verification must be supplied together"
            )
        gui_control_property_residual_document = load(args.gui_control_property_residual_anchors)
        gui_control_property_residual_verification = load(args.gui_control_property_residual_verification)
        if gui_control_property_residual_document.get("artifact") != "spectron_guicontrol_property_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control property residual artifact")
        if not gui_control_property_residual_verification.get("verified"):
            raise ValueError("GUI control property residual reopen verification did not pass")
        expected_gui_control_property_residual = len(gui_control_property_residual_document["anchors"])
        if gui_control_property_residual_verification["verified_name_count"] != expected_gui_control_property_residual:
            raise ValueError("GUI control property residual verification count differs from artifact")
        gui_control_property_residual = {
            "anchor_path": str(args.gui_control_property_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_property_residual_anchors),
            "reopen_verification": str(args.gui_control_property_residual_verification),
            "anchor_count": expected_gui_control_property_residual,
            "verified_name_count": gui_control_property_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_property_residual_verification["failure_count"],
        }
    if gui_control_property_residual is not None:
        result["gui_control_property_residual_anchors"] = gui_control_property_residual
        result["interpretation"].append(
            "The one-hundred-twenty-fifth database revision also contains the separately reviewed GuiControl property and script-wrapper residual family."
        )
    gui_control_virtual_residual = None
    if args.gui_control_virtual_residual_anchors or args.gui_control_virtual_residual_verification:
        if not args.gui_control_virtual_residual_anchors or not args.gui_control_virtual_residual_verification:
            raise ValueError(
                "GUI control virtual residual anchors and GUI control virtual residual verification must be supplied together"
            )
        gui_control_virtual_residual_document = load(args.gui_control_virtual_residual_anchors)
        gui_control_virtual_residual_verification = load(args.gui_control_virtual_residual_verification)
        if gui_control_virtual_residual_document.get("artifact") != "spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control virtual residual artifact")
        if not gui_control_virtual_residual_verification.get("verified"):
            raise ValueError("GUI control virtual residual reopen verification did not pass")
        expected_gui_control_virtual_residual = len(gui_control_virtual_residual_document["anchors"])
        if gui_control_virtual_residual_verification["verified_name_count"] != expected_gui_control_virtual_residual:
            raise ValueError("GUI control virtual residual verification count differs from artifact")
        gui_control_virtual_residual = {
            "anchor_path": str(args.gui_control_virtual_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_virtual_residual_anchors),
            "reopen_verification": str(args.gui_control_virtual_residual_verification),
            "anchor_count": expected_gui_control_virtual_residual,
            "verified_name_count": gui_control_virtual_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_virtual_residual_verification["failure_count"],
        }
    if gui_control_virtual_residual is not None:
        result["gui_control_virtual_residual_anchors"] = gui_control_virtual_residual
        result["interpretation"].append(
            "The one-hundred-twenty-sixth database revision also contains the separately reviewed GuiControl base and virtual-hook residual family."
        )
    gui_control_event_sizing_residual = None
    if args.gui_control_event_sizing_residual_anchors or args.gui_control_event_sizing_residual_verification:
        if not args.gui_control_event_sizing_residual_anchors or not args.gui_control_event_sizing_residual_verification:
            raise ValueError(
                "GUI control event and sizing residual anchors and verification must be supplied together"
            )
        gui_control_event_sizing_residual_document = load(args.gui_control_event_sizing_residual_anchors)
        gui_control_event_sizing_residual_verification = load(args.gui_control_event_sizing_residual_verification)
        if gui_control_event_sizing_residual_document.get("artifact") != "spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control event and sizing residual artifact")
        if not gui_control_event_sizing_residual_verification.get("verified"):
            raise ValueError("GUI control event and sizing residual reopen verification did not pass")
        expected_gui_control_event_sizing_residual = len(gui_control_event_sizing_residual_document["anchors"])
        if gui_control_event_sizing_residual_verification["verified_name_count"] != expected_gui_control_event_sizing_residual:
            raise ValueError("GUI control event and sizing residual verification count differs from artifact")
        gui_control_event_sizing_residual = {
            "anchor_path": str(args.gui_control_event_sizing_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_event_sizing_residual_anchors),
            "reopen_verification": str(args.gui_control_event_sizing_residual_verification),
            "anchor_count": expected_gui_control_event_sizing_residual,
            "verified_name_count": gui_control_event_sizing_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_event_sizing_residual_verification["failure_count"],
        }
    if gui_control_event_sizing_residual is not None:
        result["gui_control_event_sizing_residual_anchors"] = gui_control_event_sizing_residual
        result["interpretation"].append(
            "The one-hundred-twenty-seventh database revision also contains the separately reviewed GuiControl event and sizing residual family."
        )
    gui_control_style_bounds_residual = None
    if args.gui_control_style_bounds_residual_anchors or args.gui_control_style_bounds_residual_verification:
        if not args.gui_control_style_bounds_residual_anchors or not args.gui_control_style_bounds_residual_verification:
            raise ValueError(
                "GUI control style and bounds residual anchors and verification must be supplied together"
            )
        gui_control_style_bounds_residual_document = load(args.gui_control_style_bounds_residual_anchors)
        gui_control_style_bounds_residual_verification = load(args.gui_control_style_bounds_residual_verification)
        if gui_control_style_bounds_residual_document.get("artifact") != "spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control style and bounds residual artifact")
        if not gui_control_style_bounds_residual_verification.get("verified"):
            raise ValueError("GUI control style and bounds residual reopen verification did not pass")
        expected_gui_control_style_bounds_residual = len(gui_control_style_bounds_residual_document["anchors"])
        if gui_control_style_bounds_residual_verification["verified_name_count"] != expected_gui_control_style_bounds_residual:
            raise ValueError("GUI control style and bounds residual verification count differs from artifact")
        gui_control_style_bounds_residual = {
            "anchor_path": str(args.gui_control_style_bounds_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_style_bounds_residual_anchors),
            "reopen_verification": str(args.gui_control_style_bounds_residual_verification),
            "anchor_count": expected_gui_control_style_bounds_residual,
            "verified_name_count": gui_control_style_bounds_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_style_bounds_residual_verification["failure_count"],
        }
    if gui_control_style_bounds_residual is not None:
        result["gui_control_style_bounds_residual_anchors"] = gui_control_style_bounds_residual
        result["interpretation"].append(
            "The one-hundred-twenty-eighth database revision also contains the separately reviewed GuiControl style and bounds residual family."
        )
    gui_control_event_dispatch_residual = None
    if args.gui_control_event_dispatch_residual_anchors or args.gui_control_event_dispatch_residual_verification:
        if not args.gui_control_event_dispatch_residual_anchors or not args.gui_control_event_dispatch_residual_verification:
            raise ValueError(
                "GUI control event dispatch residual anchors and verification must be supplied together"
            )
        gui_control_event_dispatch_residual_document = load(args.gui_control_event_dispatch_residual_anchors)
        gui_control_event_dispatch_residual_verification = load(args.gui_control_event_dispatch_residual_verification)
        if gui_control_event_dispatch_residual_document.get("artifact") != "spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control event dispatch residual artifact")
        if not gui_control_event_dispatch_residual_verification.get("verified"):
            raise ValueError("GUI control event dispatch residual reopen verification did not pass")
        expected_gui_control_event_dispatch_residual = len(gui_control_event_dispatch_residual_document["anchors"])
        if gui_control_event_dispatch_residual_verification["verified_name_count"] != expected_gui_control_event_dispatch_residual:
            raise ValueError("GUI control event dispatch residual verification count differs from artifact")
        gui_control_event_dispatch_residual = {
            "anchor_path": str(args.gui_control_event_dispatch_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_event_dispatch_residual_anchors),
            "reopen_verification": str(args.gui_control_event_dispatch_residual_verification),
            "anchor_count": expected_gui_control_event_dispatch_residual,
            "verified_name_count": gui_control_event_dispatch_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_event_dispatch_residual_verification["failure_count"],
        }
    if gui_control_event_dispatch_residual is not None:
        result["gui_control_event_dispatch_residual_anchors"] = gui_control_event_dispatch_residual
        result["interpretation"].append(
            "The one-hundred-twenty-ninth database revision also contains the separately reviewed GuiControl event-dispatch residual family."
        )
    gui_control_initialization_residual = None
    if args.gui_control_initialization_residual_anchors or args.gui_control_initialization_residual_verification:
        if not args.gui_control_initialization_residual_anchors or not args.gui_control_initialization_residual_verification:
            raise ValueError(
                "GUI control initialization residual anchors and verification must be supplied together"
            )
        gui_control_initialization_residual_document = load(args.gui_control_initialization_residual_anchors)
        gui_control_initialization_residual_verification = load(args.gui_control_initialization_residual_verification)
        if gui_control_initialization_residual_document.get("artifact") != "spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control initialization residual artifact")
        if not gui_control_initialization_residual_verification.get("verified"):
            raise ValueError("GUI control initialization residual reopen verification did not pass")
        expected_gui_control_initialization_residual = len(gui_control_initialization_residual_document["anchors"])
        if gui_control_initialization_residual_verification["verified_name_count"] != expected_gui_control_initialization_residual:
            raise ValueError("GUI control initialization residual verification count differs from artifact")
        gui_control_initialization_residual = {
            "anchor_path": str(args.gui_control_initialization_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_initialization_residual_anchors),
            "reopen_verification": str(args.gui_control_initialization_residual_verification),
            "anchor_count": expected_gui_control_initialization_residual,
            "verified_name_count": gui_control_initialization_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_initialization_residual_verification["failure_count"],
        }
    if gui_control_initialization_residual is not None:
        result["gui_control_initialization_residual_anchors"] = gui_control_initialization_residual
        result["interpretation"].append(
            "The one-hundred-thirtieth database revision also contains the separately reviewed GuiControl initialization and parameterized-constructor residual family."
        )
    gui_control_create_residual = None
    if args.gui_control_create_residual_anchors or args.gui_control_create_residual_verification:
        if not args.gui_control_create_residual_anchors or not args.gui_control_create_residual_verification:
            raise ValueError(
                "GUI control create residual anchors and verification must be supplied together"
            )
        gui_control_create_residual_document = load(args.gui_control_create_residual_anchors)
        gui_control_create_residual_verification = load(args.gui_control_create_residual_verification)
        if gui_control_create_residual_document.get("artifact") != "spectron_guicontrol_create_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GUI control create residual artifact")
        if not gui_control_create_residual_verification.get("verified"):
            raise ValueError("GUI control create residual reopen verification did not pass")
        expected_gui_control_create_residual = len(gui_control_create_residual_document["anchors"])
        if gui_control_create_residual_verification["verified_name_count"] != expected_gui_control_create_residual:
            raise ValueError("GUI control create residual verification count differs from artifact")
        gui_control_create_residual = {
            "anchor_path": str(args.gui_control_create_residual_anchors),
            "anchor_sha256": sha256_path(args.gui_control_create_residual_anchors),
            "reopen_verification": str(args.gui_control_create_residual_verification),
            "anchor_count": expected_gui_control_create_residual,
            "verified_name_count": gui_control_create_residual_verification["verified_name_count"],
            "reopen_failure_count": gui_control_create_residual_verification["failure_count"],
        }
    if gui_control_create_residual is not None:
        result["gui_control_create_residual_anchors"] = gui_control_create_residual
        result["interpretation"].append(
            "The one-hundred-thirty-first database revision also contains the separately reviewed GuiControl factory-wrapper residual anchor."
        )
    tsocket_accessor_residual = None
    if args.tsocket_accessor_residual_anchors or args.tsocket_accessor_residual_verification:
        if not args.tsocket_accessor_residual_anchors or not args.tsocket_accessor_residual_verification:
            raise ValueError(
                "TSocket accessor residual anchors and verification must be supplied together"
            )
        tsocket_accessor_residual_document = load(args.tsocket_accessor_residual_anchors)
        tsocket_accessor_residual_verification = load(args.tsocket_accessor_residual_verification)
        if tsocket_accessor_residual_document.get("artifact") != "spectron_tsocket_accessor_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocket accessor residual artifact")
        if not tsocket_accessor_residual_verification.get("verified"):
            raise ValueError("TSocket accessor residual reopen verification did not pass")
        expected_tsocket_accessor_residual = len(tsocket_accessor_residual_document["anchors"])
        if tsocket_accessor_residual_verification["verified_name_count"] != expected_tsocket_accessor_residual:
            raise ValueError("TSocket accessor residual verification count differs from artifact")
        tsocket_accessor_residual = {
            "anchor_path": str(args.tsocket_accessor_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_accessor_residual_anchors),
            "reopen_verification": str(args.tsocket_accessor_residual_verification),
            "anchor_count": expected_tsocket_accessor_residual,
            "verified_name_count": tsocket_accessor_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_accessor_residual_verification["failure_count"],
        }
    if tsocket_accessor_residual is not None:
        result["tsocket_accessor_residual_anchors"] = tsocket_accessor_residual
        result["interpretation"].append(
            "The one-hundred-thirty-second database revision also contains the separately reviewed TSocket accessor, output, and factory residual family."
        )
    tsocket_ssl_residual = None
    if args.tsocket_ssl_residual_anchors or args.tsocket_ssl_residual_verification:
        if not args.tsocket_ssl_residual_anchors or not args.tsocket_ssl_residual_verification:
            raise ValueError(
                "TSocket SSL residual anchors and verification must be supplied together"
            )
        tsocket_ssl_residual_document = load(args.tsocket_ssl_residual_anchors)
        tsocket_ssl_residual_verification = load(args.tsocket_ssl_residual_verification)
        if tsocket_ssl_residual_document.get("artifact") != "spectron_tsocket_ssl_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocket SSL residual artifact")
        if not tsocket_ssl_residual_verification.get("verified"):
            raise ValueError("TSocket SSL residual reopen verification did not pass")
        expected_tsocket_ssl_residual = len(tsocket_ssl_residual_document["anchors"])
        if tsocket_ssl_residual_verification["verified_name_count"] != expected_tsocket_ssl_residual:
            raise ValueError("TSocket SSL residual verification count differs from artifact")
        tsocket_ssl_residual = {
            "anchor_path": str(args.tsocket_ssl_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_ssl_residual_anchors),
            "reopen_verification": str(args.tsocket_ssl_residual_verification),
            "anchor_count": expected_tsocket_ssl_residual,
            "verified_name_count": tsocket_ssl_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_ssl_residual_verification["failure_count"],
        }
    if tsocket_ssl_residual is not None:
        result["tsocket_ssl_residual_anchors"] = tsocket_ssl_residual
        result["interpretation"].append(
            "The one-hundred-thirty-third database revision also contains the separately reviewed TSocket SSL configuration and outgoing-buffer residual family."
        )
    tsocket_receive_residual = None
    if args.tsocket_receive_residual_anchors or args.tsocket_receive_residual_verification:
        if not args.tsocket_receive_residual_anchors or not args.tsocket_receive_residual_verification:
            raise ValueError(
                "TSocket receive residual anchors and verification must be supplied together"
            )
        tsocket_receive_residual_document = load(args.tsocket_receive_residual_anchors)
        tsocket_receive_residual_verification = load(args.tsocket_receive_residual_verification)
        if tsocket_receive_residual_document.get("artifact") != "spectron_tsocket_receive_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocket receive residual artifact")
        if not tsocket_receive_residual_verification.get("verified"):
            raise ValueError("TSocket receive residual reopen verification did not pass")
        expected_tsocket_receive_residual = len(tsocket_receive_residual_document["anchors"])
        if tsocket_receive_residual_verification["verified_name_count"] != expected_tsocket_receive_residual:
            raise ValueError("TSocket receive residual verification count differs from artifact")
        tsocket_receive_residual = {
            "anchor_path": str(args.tsocket_receive_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_receive_residual_anchors),
            "reopen_verification": str(args.tsocket_receive_residual_verification),
            "anchor_count": expected_tsocket_receive_residual,
            "verified_name_count": tsocket_receive_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_receive_residual_verification["failure_count"],
        }
    if tsocket_receive_residual is not None:
        result["tsocket_receive_residual_anchors"] = tsocket_receive_residual
        result["interpretation"].append(
            "The one-hundred-thirty-fourth database revision also contains the separately reviewed TSocket receive and data-package residual family."
        )
    tsocket_lifecycle_residual = None
    if args.tsocket_lifecycle_residual_anchors or args.tsocket_lifecycle_residual_verification:
        if not args.tsocket_lifecycle_residual_anchors or not args.tsocket_lifecycle_residual_verification:
            raise ValueError(
                "TSocket lifecycle residual anchors and verification must be supplied together"
            )
        tsocket_lifecycle_residual_document = load(args.tsocket_lifecycle_residual_anchors)
        tsocket_lifecycle_residual_verification = load(args.tsocket_lifecycle_residual_verification)
        if tsocket_lifecycle_residual_document.get("artifact") != "spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocket lifecycle residual artifact")
        if not tsocket_lifecycle_residual_verification.get("verified"):
            raise ValueError("TSocket lifecycle residual reopen verification did not pass")
        expected_tsocket_lifecycle_residual = len(tsocket_lifecycle_residual_document["anchors"])
        if tsocket_lifecycle_residual_verification["verified_name_count"] != expected_tsocket_lifecycle_residual:
            raise ValueError("TSocket lifecycle residual verification count differs from artifact")
        tsocket_lifecycle_residual = {
            "anchor_path": str(args.tsocket_lifecycle_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_lifecycle_residual_anchors),
            "reopen_verification": str(args.tsocket_lifecycle_residual_verification),
            "anchor_count": expected_tsocket_lifecycle_residual,
            "verified_name_count": tsocket_lifecycle_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_lifecycle_residual_verification["failure_count"],
        }
    if tsocket_lifecycle_residual is not None:
        result["tsocket_lifecycle_residual_anchors"] = tsocket_lifecycle_residual
        result["interpretation"].append(
            "The one-hundred-thirty-fifth database revision also contains the separately reviewed TSocket lifecycle residual family."
        )
    tsocket_host_residual = None
    if args.tsocket_host_residual_anchors or args.tsocket_host_residual_verification:
        if not args.tsocket_host_residual_anchors or not args.tsocket_host_residual_verification:
            raise ValueError(
                "TSocket host residual anchors and verification must be supplied together"
            )
        tsocket_host_residual_document = load(args.tsocket_host_residual_anchors)
        tsocket_host_residual_verification = load(args.tsocket_host_residual_verification)
        if tsocket_host_residual_document.get("artifact") != "spectron_tsocket_host_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocket host residual artifact")
        if not tsocket_host_residual_verification.get("verified"):
            raise ValueError("TSocket host residual reopen verification did not pass")
        expected_tsocket_host_residual = len(tsocket_host_residual_document["anchors"])
        if tsocket_host_residual_verification["verified_name_count"] != expected_tsocket_host_residual:
            raise ValueError("TSocket host residual verification count differs from artifact")
        tsocket_host_residual = {
            "anchor_path": str(args.tsocket_host_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_host_residual_anchors),
            "reopen_verification": str(args.tsocket_host_residual_verification),
            "anchor_count": expected_tsocket_host_residual,
            "verified_name_count": tsocket_host_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_host_residual_verification["failure_count"],
        }
    if tsocket_host_residual is not None:
        result["tsocket_host_residual_anchors"] = tsocket_host_residual
        result["interpretation"].append(
            "The one-hundred-thirty-sixth database revision also contains the separately reviewed TSocket host and logging residual family."
        )
    tsocket_properties_residual = None
    if args.tsocket_properties_residual_anchors or args.tsocket_properties_residual_verification:
        if not args.tsocket_properties_residual_anchors or not args.tsocket_properties_residual_verification:
            raise ValueError(
                "TSocketProperties residual anchors and verification must be supplied together"
            )
        tsocket_properties_residual_document = load(args.tsocket_properties_residual_anchors)
        tsocket_properties_residual_verification = load(args.tsocket_properties_residual_verification)
        if tsocket_properties_residual_document.get("artifact") != "spectron_tsocket_properties_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TSocketProperties residual artifact")
        if not tsocket_properties_residual_verification.get("verified"):
            raise ValueError("TSocketProperties residual reopen verification did not pass")
        expected_tsocket_properties_residual = len(tsocket_properties_residual_document["anchors"])
        if tsocket_properties_residual_verification["verified_name_count"] != expected_tsocket_properties_residual:
            raise ValueError("TSocketProperties residual verification count differs from artifact")
        tsocket_properties_residual = {
            "anchor_path": str(args.tsocket_properties_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_properties_residual_anchors),
            "reopen_verification": str(args.tsocket_properties_residual_verification),
            "anchor_count": expected_tsocket_properties_residual,
            "verified_name_count": tsocket_properties_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_properties_residual_verification["failure_count"],
        }
    if tsocket_properties_residual is not None:
        result["tsocket_properties_residual_anchors"] = tsocket_properties_residual
        result["interpretation"].append(
            "The one-hundred-thirty-seventh database revision also contains the separately reviewed TSocketProperties destructor family."
        )
    socket_cache_residual = None
    if args.socket_cache_residual_anchors or args.socket_cache_residual_verification:
        if not args.socket_cache_residual_anchors or not args.socket_cache_residual_verification:
            raise ValueError(
                "socket cache residual anchors and verification must be supplied together"
            )
        socket_cache_residual_document = load(args.socket_cache_residual_anchors)
        socket_cache_residual_verification = load(args.socket_cache_residual_verification)
        if socket_cache_residual_document.get("artifact") != "spectron_socket_cache_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected socket cache residual artifact")
        if not socket_cache_residual_verification.get("verified"):
            raise ValueError("socket cache residual reopen verification did not pass")
        expected_socket_cache_residual = len(socket_cache_residual_document["anchors"])
        if socket_cache_residual_verification["verified_name_count"] != expected_socket_cache_residual:
            raise ValueError("socket cache residual verification count differs from artifact")
        socket_cache_residual = {
            "anchor_path": str(args.socket_cache_residual_anchors),
            "anchor_sha256": sha256_path(args.socket_cache_residual_anchors),
            "reopen_verification": str(args.socket_cache_residual_verification),
            "anchor_count": expected_socket_cache_residual,
            "verified_name_count": socket_cache_residual_verification["verified_name_count"],
            "reopen_failure_count": socket_cache_residual_verification["failure_count"],
        }
    if socket_cache_residual is not None:
        result["socket_cache_residual_anchors"] = socket_cache_residual
        result["interpretation"].append(
            "The one-hundred-thirty-eighth database revision also contains the separately reviewed socket-cache support residual family."
        )
    url_cache_residual = None
    if args.url_cache_residual_anchors or args.url_cache_residual_verification:
        if not args.url_cache_residual_anchors or not args.url_cache_residual_verification:
            raise ValueError(
                "URL-cache residual anchors and verification must be supplied together"
            )
        url_cache_residual_document = load(args.url_cache_residual_anchors)
        url_cache_residual_verification = load(args.url_cache_residual_verification)
        if url_cache_residual_document.get("artifact") != "spectron_url_cache_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected URL-cache residual artifact")
        if not url_cache_residual_verification.get("verified"):
            raise ValueError("URL-cache residual reopen verification did not pass")
        expected_url_cache_residual = len(url_cache_residual_document["anchors"])
        if url_cache_residual_verification["verified_name_count"] != expected_url_cache_residual:
            raise ValueError("URL-cache residual verification count differs from artifact")
        url_cache_residual = {
            "anchor_path": str(args.url_cache_residual_anchors),
            "anchor_sha256": sha256_path(args.url_cache_residual_anchors),
            "reopen_verification": str(args.url_cache_residual_verification),
            "anchor_count": expected_url_cache_residual,
            "verified_name_count": url_cache_residual_verification["verified_name_count"],
            "reopen_failure_count": url_cache_residual_verification["failure_count"],
        }
    if url_cache_residual is not None:
        result["url_cache_residual_anchors"] = url_cache_residual
        result["interpretation"].append(
            "The one-hundred-thirty-ninth database revision also contains the separately reviewed URL-cache support residual family."
        )
    player_list_residual = None
    if args.player_list_residual_anchors or args.player_list_residual_verification:
        if not args.player_list_residual_anchors or not args.player_list_residual_verification:
            raise ValueError(
                "player-list residual anchors and verification must be supplied together"
            )
        player_list_residual_document = load(args.player_list_residual_anchors)
        player_list_residual_verification = load(args.player_list_residual_verification)
        if player_list_residual_document.get("artifact") != "spectron_player_list_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected player-list residual artifact")
        if not player_list_residual_verification.get("verified"):
            raise ValueError("player-list residual reopen verification did not pass")
        expected_player_list_residual = len(player_list_residual_document["anchors"])
        if player_list_residual_verification["verified_name_count"] != expected_player_list_residual:
            raise ValueError("player-list residual verification count differs from artifact")
        player_list_residual = {
            "anchor_path": str(args.player_list_residual_anchors),
            "anchor_sha256": sha256_path(args.player_list_residual_anchors),
            "reopen_verification": str(args.player_list_residual_verification),
            "anchor_count": expected_player_list_residual,
            "verified_name_count": player_list_residual_verification["verified_name_count"],
            "reopen_failure_count": player_list_residual_verification["failure_count"],
        }
    if player_list_residual is not None:
        result["player_list_residual_anchors"] = player_list_residual
        result["interpretation"].append(
            "The one-hundred-fortieth database revision also contains the separately reviewed TPlayerList residual family."
        )
    client_thread_residual = None
    if args.client_thread_residual_anchors or args.client_thread_residual_verification:
        if not args.client_thread_residual_anchors or not args.client_thread_residual_verification:
            raise ValueError(
                "client-thread residual anchors and verification must be supplied together"
            )
        client_thread_residual_document = load(args.client_thread_residual_anchors)
        client_thread_residual_verification = load(args.client_thread_residual_verification)
        if client_thread_residual_document.get("artifact") != "spectron_client_thread_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected client-thread residual artifact")
        if not client_thread_residual_verification.get("verified"):
            raise ValueError("client-thread residual reopen verification did not pass")
        expected_client_thread_residual = len(client_thread_residual_document["anchors"])
        if client_thread_residual_verification["verified_name_count"] != expected_client_thread_residual:
            raise ValueError("client-thread residual verification count differs from artifact")
        client_thread_residual = {
            "anchor_path": str(args.client_thread_residual_anchors),
            "anchor_sha256": sha256_path(args.client_thread_residual_anchors),
            "reopen_verification": str(args.client_thread_residual_verification),
            "anchor_count": expected_client_thread_residual,
            "verified_name_count": client_thread_residual_verification["verified_name_count"],
            "reopen_failure_count": client_thread_residual_verification["failure_count"],
        }
    if client_thread_residual is not None:
        result["client_thread_residual_anchors"] = client_thread_residual
        result["interpretation"].append(
            "The one-hundred-forty-first database revision also contains the separately reviewed client-thread residual family."
        )
    update_package_accessor_residual = None
    if args.update_package_accessor_residual_anchors or args.update_package_accessor_residual_verification:
        if not args.update_package_accessor_residual_anchors or not args.update_package_accessor_residual_verification:
            raise ValueError(
                "update-package accessor residual anchors and verification must be supplied together"
            )
        update_package_accessor_residual_document = load(args.update_package_accessor_residual_anchors)
        update_package_accessor_residual_verification = load(args.update_package_accessor_residual_verification)
        if update_package_accessor_residual_document.get("artifact") != "spectron_update_package_accessor_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-package accessor residual artifact")
        if not update_package_accessor_residual_verification.get("verified"):
            raise ValueError("update-package accessor residual reopen verification did not pass")
        expected_update_package_accessor_residual = len(update_package_accessor_residual_document["anchors"])
        if update_package_accessor_residual_verification["verified_name_count"] != expected_update_package_accessor_residual:
            raise ValueError("update-package accessor residual verification count differs from artifact")
        update_package_accessor_residual = {
            "anchor_path": str(args.update_package_accessor_residual_anchors),
            "anchor_sha256": sha256_path(args.update_package_accessor_residual_anchors),
            "reopen_verification": str(args.update_package_accessor_residual_verification),
            "anchor_count": expected_update_package_accessor_residual,
            "verified_name_count": update_package_accessor_residual_verification["verified_name_count"],
            "reopen_failure_count": update_package_accessor_residual_verification["failure_count"],
        }
    if update_package_accessor_residual is not None:
        result["update_package_accessor_residual_anchors"] = update_package_accessor_residual
        result["interpretation"].append(
            "The one-hundred-forty-second database revision also contains the separately reviewed update-package accessor residual family."
        )
    update_package_destructor_residual = None
    if args.update_package_destructor_residual_anchors or args.update_package_destructor_residual_verification:
        if not args.update_package_destructor_residual_anchors or not args.update_package_destructor_residual_verification:
            raise ValueError(
                "update-package destructor residual anchors and verification must be supplied together"
            )
        update_package_destructor_residual_document = load(args.update_package_destructor_residual_anchors)
        update_package_destructor_residual_verification = load(args.update_package_destructor_residual_verification)
        if update_package_destructor_residual_document.get("artifact") != "spectron_update_package_destructor_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-package destructor residual artifact")
        if not update_package_destructor_residual_verification.get("verified"):
            raise ValueError("update-package destructor residual reopen verification did not pass")
        expected_update_package_destructor_residual = len(update_package_destructor_residual_document["anchors"])
        if update_package_destructor_residual_verification["verified_name_count"] != expected_update_package_destructor_residual:
            raise ValueError("update-package destructor residual verification count differs from artifact")
        update_package_destructor_residual = {
            "anchor_path": str(args.update_package_destructor_residual_anchors),
            "anchor_sha256": sha256_path(args.update_package_destructor_residual_anchors),
            "reopen_verification": str(args.update_package_destructor_residual_verification),
            "anchor_count": expected_update_package_destructor_residual,
            "verified_name_count": update_package_destructor_residual_verification["verified_name_count"],
            "reopen_failure_count": update_package_destructor_residual_verification["failure_count"],
        }
    if update_package_destructor_residual is not None:
        result["update_package_destructor_residual_anchors"] = update_package_destructor_residual
        result["interpretation"].append(
            "The one-hundred-forty-third database revision also contains the separately reviewed update-package destructor residual family."
        )
    update_package_wrapper_residual = None
    if args.update_package_wrapper_residual_anchors or args.update_package_wrapper_residual_verification:
        if not args.update_package_wrapper_residual_anchors or not args.update_package_wrapper_residual_verification:
            raise ValueError(
                "update-package wrapper residual anchors and verification must be supplied together"
            )
        update_package_wrapper_residual_document = load(args.update_package_wrapper_residual_anchors)
        update_package_wrapper_residual_verification = load(args.update_package_wrapper_residual_verification)
        if update_package_wrapper_residual_document.get("artifact") != "spectron_update_package_wrapper_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-package wrapper residual artifact")
        if not update_package_wrapper_residual_verification.get("verified"):
            raise ValueError("update-package wrapper residual reopen verification did not pass")
        expected_update_package_wrapper_residual = len(update_package_wrapper_residual_document["anchors"])
        if update_package_wrapper_residual_verification["verified_name_count"] != expected_update_package_wrapper_residual:
            raise ValueError("update-package wrapper residual verification count differs from artifact")
        update_package_wrapper_residual = {
            "anchor_path": str(args.update_package_wrapper_residual_anchors),
            "anchor_sha256": sha256_path(args.update_package_wrapper_residual_anchors),
            "reopen_verification": str(args.update_package_wrapper_residual_verification),
            "anchor_count": expected_update_package_wrapper_residual,
            "verified_name_count": update_package_wrapper_residual_verification["verified_name_count"],
            "reopen_failure_count": update_package_wrapper_residual_verification["failure_count"],
        }
    if update_package_wrapper_residual is not None:
        result["update_package_wrapper_residual_anchors"] = update_package_wrapper_residual
        result["interpretation"].append(
            "The one-hundred-forty-fourth database revision also contains the separately reviewed update-package event and lookup wrapper residual family."
        )
    update_package_properties_residual = None
    if args.update_package_properties_residual_anchors or args.update_package_properties_residual_verification:
        if not args.update_package_properties_residual_anchors or not args.update_package_properties_residual_verification:
            raise ValueError(
                "update-package-properties residual anchors and verification must be supplied together"
            )
        update_package_properties_residual_document = load(args.update_package_properties_residual_anchors)
        update_package_properties_residual_verification = load(args.update_package_properties_residual_verification)
        if update_package_properties_residual_document.get("artifact") != "spectron_update_package_properties_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected update-package-properties residual artifact")
        if not update_package_properties_residual_verification.get("verified"):
            raise ValueError("update-package-properties residual reopen verification did not pass")
        expected_update_package_properties_residual = len(update_package_properties_residual_document["anchors"])
        if update_package_properties_residual_verification["verified_name_count"] != expected_update_package_properties_residual:
            raise ValueError("update-package-properties residual verification count differs from artifact")
        update_package_properties_residual = {
            "anchor_path": str(args.update_package_properties_residual_anchors),
            "anchor_sha256": sha256_path(args.update_package_properties_residual_anchors),
            "reopen_verification": str(args.update_package_properties_residual_verification),
            "anchor_count": expected_update_package_properties_residual,
            "verified_name_count": update_package_properties_residual_verification["verified_name_count"],
            "reopen_failure_count": update_package_properties_residual_verification["failure_count"],
        }
    if update_package_properties_residual is not None:
        result["update_package_properties_residual_anchors"] = update_package_properties_residual
        result["interpretation"].append(
            "The one-hundred-forty-fifth database revision also contains the separately reviewed update-package-properties residual family."
        )
    gsfunctions_math_string_residual = None
    if args.gsfunctions_math_string_residual_anchors or args.gsfunctions_math_string_residual_verification:
        if not args.gsfunctions_math_string_residual_anchors or not args.gsfunctions_math_string_residual_verification:
            raise ValueError(
                "GSFunctions math-string residual anchors and verification must be supplied together"
            )
        gsfunctions_math_string_residual_document = load(args.gsfunctions_math_string_residual_anchors)
        gsfunctions_math_string_residual_verification = load(args.gsfunctions_math_string_residual_verification)
        if gsfunctions_math_string_residual_document.get("artifact") != "spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions math-string residual artifact")
        if not gsfunctions_math_string_residual_verification.get("verified"):
            raise ValueError("GSFunctions math-string residual reopen verification did not pass")
        expected_gsfunctions_math_string_residual = len(gsfunctions_math_string_residual_document["anchors"])
        if gsfunctions_math_string_residual_verification["verified_name_count"] != expected_gsfunctions_math_string_residual:
            raise ValueError("GSFunctions math-string residual verification count differs from artifact")
        gsfunctions_math_string_residual = {
            "anchor_path": str(args.gsfunctions_math_string_residual_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_math_string_residual_anchors),
            "reopen_verification": str(args.gsfunctions_math_string_residual_verification),
            "anchor_count": expected_gsfunctions_math_string_residual,
            "verified_name_count": gsfunctions_math_string_residual_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_math_string_residual_verification["failure_count"],
        }
    if gsfunctions_math_string_residual is not None:
        result["gsfunctions_math_string_residual_anchors"] = gsfunctions_math_string_residual
        result["interpretation"].append(
            "The one-hundred-forty-sixth database revision also contains the separately reviewed GSFunctions math and string residual family."
        )
    gsfunctions_callback_residual = None
    if args.gsfunctions_callback_residual_anchors or args.gsfunctions_callback_residual_verification:
        if not args.gsfunctions_callback_residual_anchors or not args.gsfunctions_callback_residual_verification:
            raise ValueError(
                "GSFunctions callback residual anchors and verification must be supplied together"
            )
        gsfunctions_callback_residual_document = load(args.gsfunctions_callback_residual_anchors)
        gsfunctions_callback_residual_verification = load(args.gsfunctions_callback_residual_verification)
        if gsfunctions_callback_residual_document.get("artifact") != "spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions callback residual artifact")
        if not gsfunctions_callback_residual_verification.get("verified"):
            raise ValueError("GSFunctions callback residual reopen verification did not pass")
        expected_gsfunctions_callback_residual = len(gsfunctions_callback_residual_document["anchors"])
        if gsfunctions_callback_residual_verification["verified_name_count"] != expected_gsfunctions_callback_residual:
            raise ValueError("GSFunctions callback residual verification count differs from artifact")
        gsfunctions_callback_residual = {
            "anchor_path": str(args.gsfunctions_callback_residual_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_callback_residual_anchors),
            "reopen_verification": str(args.gsfunctions_callback_residual_verification),
            "anchor_count": expected_gsfunctions_callback_residual,
            "verified_name_count": gsfunctions_callback_residual_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_callback_residual_verification["failure_count"],
        }
    if gsfunctions_callback_residual is not None:
        result["gsfunctions_callback_residual_anchors"] = gsfunctions_callback_residual
        result["interpretation"].append(
            "The one-hundred-forty-seventh database revision also contains the separately reviewed remaining GSFunctions callback family."
        )
    gsfunctions_randomstring_residual = None
    if args.gsfunctions_randomstring_residual_anchors or args.gsfunctions_randomstring_residual_verification:
        if not args.gsfunctions_randomstring_residual_anchors or not args.gsfunctions_randomstring_residual_verification:
            raise ValueError(
                "GSFunctions randomstring residual anchors and verification must be supplied together"
            )
        gsfunctions_randomstring_residual_document = load(args.gsfunctions_randomstring_residual_anchors)
        gsfunctions_randomstring_residual_verification = load(args.gsfunctions_randomstring_residual_verification)
        if gsfunctions_randomstring_residual_document.get("artifact") != "spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions randomstring residual artifact")
        if not gsfunctions_randomstring_residual_verification.get("verified"):
            raise ValueError("GSFunctions randomstring residual reopen verification did not pass")
        expected_gsfunctions_randomstring_residual = len(gsfunctions_randomstring_residual_document["anchors"])
        if gsfunctions_randomstring_residual_verification["verified_name_count"] != expected_gsfunctions_randomstring_residual:
            raise ValueError("GSFunctions randomstring residual verification count differs from artifact")
        gsfunctions_randomstring_residual = {
            "anchor_path": str(args.gsfunctions_randomstring_residual_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_randomstring_residual_anchors),
            "reopen_verification": str(args.gsfunctions_randomstring_residual_verification),
            "anchor_count": expected_gsfunctions_randomstring_residual,
            "verified_name_count": gsfunctions_randomstring_residual_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_randomstring_residual_verification["failure_count"],
        }
    if gsfunctions_randomstring_residual is not None:
        result["gsfunctions_randomstring_residual_anchors"] = gsfunctions_randomstring_residual
        result["interpretation"].append(
            "The one-hundred-forty-ninth database revision also contains the separately reviewed GSFunctions randomstring callback."
        )
    gsfunctions_client_exact_residual = None
    if args.gsfunctions_client_exact_residual_anchors or args.gsfunctions_client_exact_residual_verification:
        if not args.gsfunctions_client_exact_residual_anchors or not args.gsfunctions_client_exact_residual_verification:
            raise ValueError(
                "GSFunctions client exact residual anchors and verification must be supplied together"
            )
        gsfunctions_client_exact_residual_document = load(args.gsfunctions_client_exact_residual_anchors)
        gsfunctions_client_exact_residual_verification = load(args.gsfunctions_client_exact_residual_verification)
        if gsfunctions_client_exact_residual_document.get("artifact") != "spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions client exact residual artifact")
        if not gsfunctions_client_exact_residual_verification.get("verified"):
            raise ValueError("GSFunctions client exact residual reopen verification did not pass")
        expected_gsfunctions_client_exact_residual = len(gsfunctions_client_exact_residual_document["anchors"])
        if gsfunctions_client_exact_residual_verification["verified_name_count"] != expected_gsfunctions_client_exact_residual:
            raise ValueError("GSFunctions client exact residual verification count differs from artifact")
        gsfunctions_client_exact_residual = {
            "anchor_path": str(args.gsfunctions_client_exact_residual_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_client_exact_residual_anchors),
            "reopen_verification": str(args.gsfunctions_client_exact_residual_verification),
            "anchor_count": expected_gsfunctions_client_exact_residual,
            "verified_name_count": gsfunctions_client_exact_residual_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_client_exact_residual_verification["failure_count"],
        }
    if gsfunctions_client_exact_residual is not None:
        result["gsfunctions_client_exact_residual_anchors"] = gsfunctions_client_exact_residual
        result["interpretation"].append(
            "The one-hundred-fiftieth database revision also contains the separately reviewed exact-shape GSFunctionsClient callback batch."
        )
    gsfunctions_client_exact_residual_v2 = None
    if args.gsfunctions_client_exact_residual_v2_anchors or args.gsfunctions_client_exact_residual_v2_verification:
        if not args.gsfunctions_client_exact_residual_v2_anchors or not args.gsfunctions_client_exact_residual_v2_verification:
            raise ValueError(
                "GSFunctions client exact residual v2 anchors and verification must be supplied together"
            )
        gsfunctions_client_exact_residual_v2_document = load(args.gsfunctions_client_exact_residual_v2_anchors)
        gsfunctions_client_exact_residual_v2_verification = load(args.gsfunctions_client_exact_residual_v2_verification)
        if gsfunctions_client_exact_residual_v2_document.get("artifact") != "spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions client exact residual v2 artifact")
        if not gsfunctions_client_exact_residual_v2_verification.get("verified"):
            raise ValueError("GSFunctions client exact residual v2 reopen verification did not pass")
        expected_gsfunctions_client_exact_residual_v2 = len(gsfunctions_client_exact_residual_v2_document["anchors"])
        if gsfunctions_client_exact_residual_v2_verification["verified_name_count"] != expected_gsfunctions_client_exact_residual_v2:
            raise ValueError("GSFunctions client exact residual v2 verification count differs from artifact")
        gsfunctions_client_exact_residual_v2 = {
            "anchor_path": str(args.gsfunctions_client_exact_residual_v2_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_client_exact_residual_v2_anchors),
            "reopen_verification": str(args.gsfunctions_client_exact_residual_v2_verification),
            "anchor_count": expected_gsfunctions_client_exact_residual_v2,
            "verified_name_count": gsfunctions_client_exact_residual_v2_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_client_exact_residual_v2_verification["failure_count"],
        }
    if gsfunctions_client_exact_residual_v2 is not None:
        result["gsfunctions_client_exact_residual_v2_anchors"] = gsfunctions_client_exact_residual_v2
        result["interpretation"].append(
            "The one-hundred-fifty-first database revision also contains the separately reviewed second exact-shape GSFunctionsClient callback batch."
        )
    gsfunctions_client_exact_residual_v3 = None
    if args.gsfunctions_client_exact_residual_v3_anchors or args.gsfunctions_client_exact_residual_v3_verification:
        if not args.gsfunctions_client_exact_residual_v3_anchors or not args.gsfunctions_client_exact_residual_v3_verification:
            raise ValueError(
                "GSFunctions client exact residual v3 anchors and verification must be supplied together"
            )
        gsfunctions_client_exact_residual_v3_document = load(args.gsfunctions_client_exact_residual_v3_anchors)
        gsfunctions_client_exact_residual_v3_verification = load(args.gsfunctions_client_exact_residual_v3_verification)
        if gsfunctions_client_exact_residual_v3_document.get("artifact") != "spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions client exact residual v3 artifact")
        if not gsfunctions_client_exact_residual_v3_verification.get("verified"):
            raise ValueError("GSFunctions client exact residual v3 reopen verification did not pass")
        expected_gsfunctions_client_exact_residual_v3 = len(gsfunctions_client_exact_residual_v3_document["anchors"])
        if gsfunctions_client_exact_residual_v3_verification["verified_name_count"] != expected_gsfunctions_client_exact_residual_v3:
            raise ValueError("GSFunctions client exact residual v3 verification count differs from artifact")
        gsfunctions_client_exact_residual_v3 = {
            "anchor_path": str(args.gsfunctions_client_exact_residual_v3_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_client_exact_residual_v3_anchors),
            "reopen_verification": str(args.gsfunctions_client_exact_residual_v3_verification),
            "anchor_count": expected_gsfunctions_client_exact_residual_v3,
            "verified_name_count": gsfunctions_client_exact_residual_v3_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_client_exact_residual_v3_verification["failure_count"],
        }
    if gsfunctions_client_exact_residual_v3 is not None:
        result["gsfunctions_client_exact_residual_v3_anchors"] = gsfunctions_client_exact_residual_v3
        result["interpretation"].append(
            "The one-hundred-fifty-second database revision also contains the separately reviewed third exact-shape GSFunctionsClient callback batch."
        )
    gsfunctions_client_boundary_residual = None
    if args.gsfunctions_client_boundary_residual_anchors or args.gsfunctions_client_boundary_residual_verification:
        if not args.gsfunctions_client_boundary_residual_anchors or not args.gsfunctions_client_boundary_residual_verification:
            raise ValueError(
                "GSFunctions client boundary residual anchors and verification must be supplied together"
            )
        gsfunctions_client_boundary_residual_document = load(args.gsfunctions_client_boundary_residual_anchors)
        gsfunctions_client_boundary_residual_verification = load(args.gsfunctions_client_boundary_residual_verification)
        if gsfunctions_client_boundary_residual_document.get("artifact") != "spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions client boundary residual artifact")
        if not gsfunctions_client_boundary_residual_verification.get("verified"):
            raise ValueError("GSFunctions client boundary residual reopen verification did not pass")
        expected_gsfunctions_client_boundary_residual = len(gsfunctions_client_boundary_residual_document["anchors"])
        if gsfunctions_client_boundary_residual_verification["verified_name_count"] != expected_gsfunctions_client_boundary_residual:
            raise ValueError("GSFunctions client boundary residual verification count differs from artifact")
        gsfunctions_client_boundary_residual = {
            "anchor_path": str(args.gsfunctions_client_boundary_residual_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_client_boundary_residual_anchors),
            "reopen_verification": str(args.gsfunctions_client_boundary_residual_verification),
            "anchor_count": expected_gsfunctions_client_boundary_residual,
            "verified_name_count": gsfunctions_client_boundary_residual_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_client_boundary_residual_verification["failure_count"],
        }
    if gsfunctions_client_boundary_residual is not None:
        result["gsfunctions_client_boundary_residual_anchors"] = gsfunctions_client_boundary_residual
        result["interpretation"].append(
            "The one-hundred-fifty-third database revision also contains the separately reviewed raw-boundary GSFunctionsClient callbacks."
        )
    gsfunctions_client_exact_residual_v4 = None
    if args.gsfunctions_client_exact_residual_v4_anchors or args.gsfunctions_client_exact_residual_v4_verification:
        if not args.gsfunctions_client_exact_residual_v4_anchors or not args.gsfunctions_client_exact_residual_v4_verification:
            raise ValueError(
                "GSFunctions client exact residual v4 anchors and verification must be supplied together"
            )
        gsfunctions_client_exact_residual_v4_document = load(args.gsfunctions_client_exact_residual_v4_anchors)
        gsfunctions_client_exact_residual_v4_verification = load(args.gsfunctions_client_exact_residual_v4_verification)
        if gsfunctions_client_exact_residual_v4_document.get("artifact") != "spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826":
            raise ValueError("unexpected GSFunctions client exact residual v4 artifact")
        if not gsfunctions_client_exact_residual_v4_verification.get("verified"):
            raise ValueError("GSFunctions client exact residual v4 reopen verification did not pass")
        expected_gsfunctions_client_exact_residual_v4 = len(gsfunctions_client_exact_residual_v4_document["anchors"])
        if gsfunctions_client_exact_residual_v4_verification["verified_name_count"] != expected_gsfunctions_client_exact_residual_v4:
            raise ValueError("GSFunctions client exact residual v4 verification count differs from artifact")
        gsfunctions_client_exact_residual_v4 = {
            "anchor_path": str(args.gsfunctions_client_exact_residual_v4_anchors),
            "anchor_sha256": sha256_path(args.gsfunctions_client_exact_residual_v4_anchors),
            "reopen_verification": str(args.gsfunctions_client_exact_residual_v4_verification),
            "anchor_count": expected_gsfunctions_client_exact_residual_v4,
            "verified_name_count": gsfunctions_client_exact_residual_v4_verification["verified_name_count"],
            "reopen_failure_count": gsfunctions_client_exact_residual_v4_verification["failure_count"],
        }
    if gsfunctions_client_exact_residual_v4 is not None:
        result["gsfunctions_client_exact_residual_v4_anchors"] = gsfunctions_client_exact_residual_v4
        result["interpretation"].append(
            "The one-hundred-fifty-fourth database revision also contains the separately reviewed fourth exact-shape GSFunctionsClient callback batch."
        )
    cyaint_tls_residual = None
    if args.cyaint_tls_residual_anchors or args.cyaint_tls_residual_verification:
        if not args.cyaint_tls_residual_anchors or not args.cyaint_tls_residual_verification:
            raise ValueError(
                "CyaInt TLS residual anchors and verification must be supplied together"
            )
        cyaint_tls_residual_document = load(args.cyaint_tls_residual_anchors)
        cyaint_tls_residual_verification = load(args.cyaint_tls_residual_verification)
        if cyaint_tls_residual_document.get("artifact") != "spectron_cyaint_tls_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected CyaInt TLS residual artifact")
        if not cyaint_tls_residual_verification.get("verified"):
            raise ValueError("CyaInt TLS residual reopen verification did not pass")
        expected_cyaint_tls_residual = len(cyaint_tls_residual_document["anchors"])
        if cyaint_tls_residual_verification["verified_name_count"] != expected_cyaint_tls_residual:
            raise ValueError("CyaInt TLS residual verification count differs from artifact")
        cyaint_tls_residual = {
            "anchor_path": str(args.cyaint_tls_residual_anchors),
            "anchor_sha256": sha256_path(args.cyaint_tls_residual_anchors),
            "reopen_verification": str(args.cyaint_tls_residual_verification),
            "anchor_count": expected_cyaint_tls_residual,
            "verified_name_count": cyaint_tls_residual_verification["verified_name_count"],
            "reopen_failure_count": cyaint_tls_residual_verification["failure_count"],
        }
    if cyaint_tls_residual is not None:
        result["cyaint_tls_residual_anchors"] = cyaint_tls_residual
        result["interpretation"].append(
            "The one-hundred-fifty-fifth database revision also contains the separately reviewed exact-shape CyaInt TLS and cryptography residual batch."
        )
    cyaint_tls_residual_v2 = None
    if args.cyaint_tls_residual_v2_anchors or args.cyaint_tls_residual_v2_verification:
        if not args.cyaint_tls_residual_v2_anchors or not args.cyaint_tls_residual_v2_verification:
            raise ValueError(
                "CyaInt TLS residual v2 anchors and verification must be supplied together"
            )
        cyaint_tls_residual_v2_document = load(args.cyaint_tls_residual_v2_anchors)
        cyaint_tls_residual_v2_verification = load(args.cyaint_tls_residual_v2_verification)
        if cyaint_tls_residual_v2_document.get("artifact") != "spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826":
            raise ValueError("unexpected CyaInt TLS residual v2 artifact")
        if not cyaint_tls_residual_v2_verification.get("verified"):
            raise ValueError("CyaInt TLS residual v2 reopen verification did not pass")
        expected_cyaint_tls_residual_v2 = len(cyaint_tls_residual_v2_document["anchors"])
        if cyaint_tls_residual_v2_verification["verified_name_count"] != expected_cyaint_tls_residual_v2:
            raise ValueError("CyaInt TLS residual v2 verification count differs from artifact")
        cyaint_tls_residual_v2 = {
            "anchor_path": str(args.cyaint_tls_residual_v2_anchors),
            "anchor_sha256": sha256_path(args.cyaint_tls_residual_v2_anchors),
            "reopen_verification": str(args.cyaint_tls_residual_v2_verification),
            "anchor_count": expected_cyaint_tls_residual_v2,
            "verified_name_count": cyaint_tls_residual_v2_verification["verified_name_count"],
            "reopen_failure_count": cyaint_tls_residual_v2_verification["failure_count"],
        }
    if cyaint_tls_residual_v2 is not None:
        result["cyaint_tls_residual_v2_anchors"] = cyaint_tls_residual_v2
        result["interpretation"].append(
            "The one-hundred-fifty-sixth database revision also contains the separately reviewed second exact-shape CyaInt TLS and cryptography residual batch."
        )
    tserverplayer_accessor = None
    if args.tserverplayer_accessor_anchors or args.tserverplayer_accessor_verification:
        if not args.tserverplayer_accessor_anchors or not args.tserverplayer_accessor_verification:
            raise ValueError(
                "TServerPlayer accessor anchors and verification must be supplied together"
            )
        tserverplayer_accessor_document = load(args.tserverplayer_accessor_anchors)
        tserverplayer_accessor_verification = load(args.tserverplayer_accessor_verification)
        if tserverplayer_accessor_document.get("artifact") != "spectron_tserverplayer_accessor_manual_translation_anchors_20260826":
            raise ValueError("unexpected TServerPlayer accessor artifact")
        if not tserverplayer_accessor_verification.get("verified"):
            raise ValueError("TServerPlayer accessor reopen verification did not pass")
        expected_tserverplayer_accessor = len(tserverplayer_accessor_document["anchors"])
        if tserverplayer_accessor_verification["verified_name_count"] != expected_tserverplayer_accessor:
            raise ValueError("TServerPlayer accessor verification count differs from artifact")
        tserverplayer_accessor = {
            "anchor_path": str(args.tserverplayer_accessor_anchors),
            "anchor_sha256": sha256_path(args.tserverplayer_accessor_anchors),
            "reopen_verification": str(args.tserverplayer_accessor_verification),
            "anchor_count": expected_tserverplayer_accessor,
            "verified_name_count": tserverplayer_accessor_verification["verified_name_count"],
            "reopen_failure_count": tserverplayer_accessor_verification["failure_count"],
        }
    if tserverplayer_accessor is not None:
        result["tserverplayer_accessor_anchors"] = tserverplayer_accessor
        result["interpretation"].append(
            "The one-hundred-fifty-seventh database revision also contains the separately reviewed exact-shape TServerPlayer scalar accessor block."
        )
    tplayer_scalar_setter = None
    if args.tplayer_scalar_setter_anchors or args.tplayer_scalar_setter_verification:
        if not args.tplayer_scalar_setter_anchors or not args.tplayer_scalar_setter_verification:
            raise ValueError(
                "TPlayer scalar setter anchors and verification must be supplied together"
            )
        tplayer_scalar_setter_document = load(args.tplayer_scalar_setter_anchors)
        tplayer_scalar_setter_verification = load(args.tplayer_scalar_setter_verification)
        if tplayer_scalar_setter_document.get("artifact") != "spectron_tplayer_scalar_setter_manual_translation_anchors_20260826":
            raise ValueError("unexpected TPlayer scalar setter artifact")
        if not tplayer_scalar_setter_verification.get("verified"):
            raise ValueError("TPlayer scalar setter reopen verification did not pass")
        expected_tplayer_scalar_setter = len(tplayer_scalar_setter_document["anchors"])
        if tplayer_scalar_setter_verification["verified_name_count"] != expected_tplayer_scalar_setter:
            raise ValueError("TPlayer scalar setter verification count differs from artifact")
        tplayer_scalar_setter = {
            "anchor_path": str(args.tplayer_scalar_setter_anchors),
            "anchor_sha256": sha256_path(args.tplayer_scalar_setter_anchors),
            "reopen_verification": str(args.tplayer_scalar_setter_verification),
            "anchor_count": expected_tplayer_scalar_setter,
            "verified_name_count": tplayer_scalar_setter_verification["verified_name_count"],
            "reopen_failure_count": tplayer_scalar_setter_verification["failure_count"],
        }
    if tplayer_scalar_setter is not None:
        result["tplayer_scalar_setter_anchors"] = tplayer_scalar_setter
        result["interpretation"].append(
            "The one-hundred-fifty-eighth database revision also contains the separately reviewed exact-shape TPlayer scalar setter block."
        )
    tplayer_scalar_getter = None
    if args.tplayer_scalar_getter_anchors or args.tplayer_scalar_getter_verification:
        if not args.tplayer_scalar_getter_anchors or not args.tplayer_scalar_getter_verification:
            raise ValueError(
                "TPlayer scalar getter anchors and verification must be supplied together"
            )
        tplayer_scalar_getter_document = load(args.tplayer_scalar_getter_anchors)
        tplayer_scalar_getter_verification = load(args.tplayer_scalar_getter_verification)
        if tplayer_scalar_getter_document.get("artifact") != "spectron_tplayer_scalar_getter_manual_translation_anchors_20260826":
            raise ValueError("unexpected TPlayer scalar getter artifact")
        if not tplayer_scalar_getter_verification.get("verified"):
            raise ValueError("TPlayer scalar getter reopen verification did not pass")
        expected_tplayer_scalar_getter = len(tplayer_scalar_getter_document["anchors"])
        if tplayer_scalar_getter_verification["verified_name_count"] != expected_tplayer_scalar_getter:
            raise ValueError("TPlayer scalar getter verification count differs from artifact")
        tplayer_scalar_getter = {
            "anchor_path": str(args.tplayer_scalar_getter_anchors),
            "anchor_sha256": sha256_path(args.tplayer_scalar_getter_anchors),
            "reopen_verification": str(args.tplayer_scalar_getter_verification),
            "anchor_count": expected_tplayer_scalar_getter,
            "verified_name_count": tplayer_scalar_getter_verification["verified_name_count"],
            "reopen_failure_count": tplayer_scalar_getter_verification["failure_count"],
        }
    if tplayer_scalar_getter is not None:
        result["tplayer_scalar_getter_anchors"] = tplayer_scalar_getter
        result["interpretation"].append(
            "The one-hundred-fifty-ninth database revision also contains the separately reviewed exact-shape TPlayer scalar getter block."
        )
    tplayer_flag_setter = None
    if args.tplayer_flag_setter_anchors or args.tplayer_flag_setter_verification:
        if not args.tplayer_flag_setter_anchors or not args.tplayer_flag_setter_verification:
            raise ValueError(
                "TPlayer flag setter anchors and verification must be supplied together"
            )
        tplayer_flag_setter_document = load(args.tplayer_flag_setter_anchors)
        tplayer_flag_setter_verification = load(args.tplayer_flag_setter_verification)
        if tplayer_flag_setter_document.get("artifact") != "spectron_tplayer_flag_setter_manual_translation_anchors_20260826":
            raise ValueError("unexpected TPlayer flag setter artifact")
        if not tplayer_flag_setter_verification.get("verified"):
            raise ValueError("TPlayer flag setter reopen verification did not pass")
        expected_tplayer_flag_setter = len(tplayer_flag_setter_document["anchors"])
        if tplayer_flag_setter_verification["verified_name_count"] != expected_tplayer_flag_setter:
            raise ValueError("TPlayer flag setter verification count differs from artifact")
        tplayer_flag_setter = {
            "anchor_path": str(args.tplayer_flag_setter_anchors),
            "anchor_sha256": sha256_path(args.tplayer_flag_setter_anchors),
            "reopen_verification": str(args.tplayer_flag_setter_verification),
            "anchor_count": expected_tplayer_flag_setter,
            "verified_name_count": tplayer_flag_setter_verification["verified_name_count"],
            "reopen_failure_count": tplayer_flag_setter_verification["failure_count"],
        }
    if tplayer_flag_setter is not None:
        result["tplayer_flag_setter_anchors"] = tplayer_flag_setter
        result["interpretation"].append(
            "The one-hundred-sixtieth database revision also contains the separately reviewed exact-shape TPlayer flag-setter block."
        )
    tserverplayer_property_block = None
    if args.tserverplayer_property_block_anchors or args.tserverplayer_property_block_verification:
        if not args.tserverplayer_property_block_anchors or not args.tserverplayer_property_block_verification:
            raise ValueError(
                "TServerPlayer property-block anchors and verification must be supplied together"
            )
        tserverplayer_property_block_document = load(args.tserverplayer_property_block_anchors)
        tserverplayer_property_block_verification = load(args.tserverplayer_property_block_verification)
        if tserverplayer_property_block_document.get("artifact") != "spectron_tserverplayer_property_block_manual_translation_anchors_20260826":
            raise ValueError("unexpected TServerPlayer property-block artifact")
        if not tserverplayer_property_block_verification.get("verified"):
            raise ValueError("TServerPlayer property-block reopen verification did not pass")
        expected_tserverplayer_property_block = len(tserverplayer_property_block_document["anchors"])
        if tserverplayer_property_block_verification["verified_name_count"] != expected_tserverplayer_property_block:
            raise ValueError("TServerPlayer property-block verification count differs from artifact")
        tserverplayer_property_block = {
            "anchor_path": str(args.tserverplayer_property_block_anchors),
            "anchor_sha256": sha256_path(args.tserverplayer_property_block_anchors),
            "reopen_verification": str(args.tserverplayer_property_block_verification),
            "anchor_count": expected_tserverplayer_property_block,
            "verified_name_count": tserverplayer_property_block_verification["verified_name_count"],
            "reopen_failure_count": tserverplayer_property_block_verification["failure_count"],
        }
    if tserverplayer_property_block is not None:
        result["tserverplayer_property_block_anchors"] = tserverplayer_property_block
        result["interpretation"].append(
            "The one-hundred-sixty-first database revision also contains the separately reviewed exact-shape TServerPlayer property block."
        )
    tserverplayer_residual = None
    if args.tserverplayer_residual_anchors or args.tserverplayer_residual_verification:
        if not args.tserverplayer_residual_anchors or not args.tserverplayer_residual_verification:
            raise ValueError(
                "TServerPlayer residual anchors and verification must be supplied together"
            )
        tserverplayer_residual_document = load(args.tserverplayer_residual_anchors)
        tserverplayer_residual_verification = load(args.tserverplayer_residual_verification)
        if tserverplayer_residual_document.get("artifact") != "spectron_tserverplayer_residual_manual_translation_anchors_20260826":
            raise ValueError("unexpected TServerPlayer residual artifact")
        if not tserverplayer_residual_verification.get("verified"):
            raise ValueError("TServerPlayer residual reopen verification did not pass")
        expected_tserverplayer_residual = len(tserverplayer_residual_document["anchors"])
        if tserverplayer_residual_verification["verified_name_count"] != expected_tserverplayer_residual:
            raise ValueError("TServerPlayer residual verification count differs from artifact")
        tserverplayer_residual = {
            "anchor_path": str(args.tserverplayer_residual_anchors),
            "anchor_sha256": sha256_path(args.tserverplayer_residual_anchors),
            "reopen_verification": str(args.tserverplayer_residual_verification),
            "anchor_count": expected_tserverplayer_residual,
            "verified_name_count": tserverplayer_residual_verification["verified_name_count"],
            "reopen_failure_count": tserverplayer_residual_verification["failure_count"],
        }
    if tserverplayer_residual is not None:
        result["tserverplayer_residual_anchors"] = tserverplayer_residual
        result["interpretation"].append(
            "The one-hundred-sixty-third database revision also contains the separately reviewed TServerPlayer registration-table callback anchors."
        )
    tserverplayer_tail = None
    if args.tserverplayer_tail_anchors or args.tserverplayer_tail_verification:
        if not args.tserverplayer_tail_anchors or not args.tserverplayer_tail_verification:
            raise ValueError(
                "TServerPlayer tail anchors and verification must be supplied together"
            )
        tserverplayer_tail_document = load(args.tserverplayer_tail_anchors)
        tserverplayer_tail_verification = load(args.tserverplayer_tail_verification)
        if tserverplayer_tail_document.get("artifact") != "spectron_tserverplayer_tail_manual_translation_anchors_20260826":
            raise ValueError("unexpected TServerPlayer tail artifact")
        if not tserverplayer_tail_verification.get("verified"):
            raise ValueError("TServerPlayer tail reopen verification did not pass")
        expected_tserverplayer_tail = len(tserverplayer_tail_document["anchors"])
        if tserverplayer_tail_verification["verified_name_count"] != expected_tserverplayer_tail:
            raise ValueError("TServerPlayer tail verification count differs from artifact")
        tserverplayer_tail = {
            "anchor_path": str(args.tserverplayer_tail_anchors),
            "anchor_sha256": sha256_path(args.tserverplayer_tail_anchors),
            "reopen_verification": str(args.tserverplayer_tail_verification),
            "anchor_count": expected_tserverplayer_tail,
            "verified_name_count": tserverplayer_tail_verification["verified_name_count"],
            "reopen_failure_count": tserverplayer_tail_verification["failure_count"],
        }
    if tserverplayer_tail is not None:
        result["tserverplayer_tail_anchors"] = tserverplayer_tail
        result["interpretation"].append(
            "The one-hundred-sixty-fourth database revision also contains the separately reviewed TServerPlayer lifecycle, static-initializer, attachment, and coordinate-tail anchors."
        )
    http_request_receive = None
    if args.http_request_receive_anchors or args.http_request_receive_verification:
        if not args.http_request_receive_anchors or not args.http_request_receive_verification:
            raise ValueError(
                "HTTP request receive anchors and verification must be supplied together"
            )
        http_request_receive_document = load(args.http_request_receive_anchors)
        http_request_receive_verification = load(args.http_request_receive_verification)
        if http_request_receive_document.get("artifact") != "spectron_http_request_receive_manual_translation_anchors_20260827":
            raise ValueError("unexpected HTTP request receive anchor artifact")
        if not http_request_receive_verification.get("verified"):
            raise ValueError("HTTP request receive anchor reopen verification did not pass")
        expected_http_request_receive = len(http_request_receive_document["anchors"])
        if http_request_receive_verification["verified_name_count"] != expected_http_request_receive:
            raise ValueError("HTTP request receive verification count differs from artifact")
        http_request_receive = {
            "anchor_path": str(args.http_request_receive_anchors),
            "anchor_sha256": sha256_path(args.http_request_receive_anchors),
            "reopen_verification": str(args.http_request_receive_verification),
            "anchor_count": expected_http_request_receive,
            "verified_name_count": http_request_receive_verification["verified_name_count"],
            "reopen_failure_count": http_request_receive_verification["failure_count"],
        }
    if http_request_receive is not None:
        result["http_request_receive_anchors"] = http_request_receive
        result["interpretation"].append(
            "The v177 database revision also contains the separately reviewed HTTP response read and data-parser anchors."
        )
    server_list_connection = None
    if args.server_list_connection_anchors or args.server_list_connection_verification:
        if not args.server_list_connection_anchors or not args.server_list_connection_verification:
            raise ValueError(
                "server-list connection anchors and verification must be supplied together"
            )
        server_list_connection_document = load(args.server_list_connection_anchors)
        server_list_connection_verification = load(args.server_list_connection_verification)
        if server_list_connection_document.get("artifact") != "spectron_server_list_connection_manual_translation_anchors_20260827":
            raise ValueError("unexpected server-list connection anchor artifact")
        if not server_list_connection_verification.get("verified"):
            raise ValueError("server-list connection anchor reopen verification did not pass")
        expected_server_list_connection = len(server_list_connection_document["anchors"])
        if server_list_connection_verification["verified_name_count"] != expected_server_list_connection:
            raise ValueError("server-list connection verification count differs from artifact")
        server_list_connection = {
            "anchor_path": str(args.server_list_connection_anchors),
            "anchor_sha256": sha256_path(args.server_list_connection_anchors),
            "reopen_verification": str(args.server_list_connection_verification),
            "anchor_count": expected_server_list_connection,
            "verified_name_count": server_list_connection_verification["verified_name_count"],
            "reopen_failure_count": server_list_connection_verification["failure_count"],
        }
    if server_list_connection is not None:
        result["server_list_connection_anchors"] = server_list_connection
        result["interpretation"].append(
            "The v178 database revision also contains the separately reviewed server-list getter and connection-handoff anchors."
        )
    server_list_state = None
    if args.server_list_state_anchors or args.server_list_state_verification:
        if not args.server_list_state_anchors or not args.server_list_state_verification:
            raise ValueError(
                "server-list state anchors and verification must be supplied together"
            )
        server_list_state_document = load(args.server_list_state_anchors)
        server_list_state_verification = load(args.server_list_state_verification)
        if server_list_state_document.get("artifact") != "spectron_server_list_state_manual_translation_anchors_20260827":
            raise ValueError("unexpected server-list state anchor artifact")
        if not server_list_state_verification.get("verified"):
            raise ValueError("server-list state anchor reopen verification did not pass")
        expected_server_list_state = len(server_list_state_document["anchors"])
        if server_list_state_verification["verified_name_count"] != expected_server_list_state:
            raise ValueError("server-list state verification count differs from artifact")
        server_list_state = {
            "anchor_path": str(args.server_list_state_anchors),
            "anchor_sha256": sha256_path(args.server_list_state_anchors),
            "reopen_verification": str(args.server_list_state_verification),
            "anchor_count": expected_server_list_state,
            "verified_name_count": server_list_state_verification["verified_name_count"],
            "reopen_failure_count": server_list_state_verification["failure_count"],
        }
    if server_list_state is not None:
        result["server_list_state_anchors"] = server_list_state
        result["interpretation"].append(
            "The v179 database revision also contains the separately reviewed server-list boolean and start-parameter state anchors."
        )
    http_request_cleanup = None
    if args.http_request_cleanup_anchors or args.http_request_cleanup_verification:
        if not args.http_request_cleanup_anchors or not args.http_request_cleanup_verification:
            raise ValueError(
                "HTTP request cleanup anchors and verification must be supplied together"
            )
        http_request_cleanup_document = load(args.http_request_cleanup_anchors)
        http_request_cleanup_verification = load(args.http_request_cleanup_verification)
        if http_request_cleanup_document.get("artifact") != "spectron_http_request_cleanup_manual_translation_anchors_20260827":
            raise ValueError("unexpected HTTP request cleanup anchor artifact")
        if not http_request_cleanup_verification.get("verified"):
            raise ValueError("HTTP request cleanup anchor reopen verification did not pass")
        expected_http_request_cleanup = len(http_request_cleanup_document["anchors"])
        if http_request_cleanup_verification["verified_name_count"] != expected_http_request_cleanup:
            raise ValueError("HTTP request cleanup verification count differs from artifact")
        http_request_cleanup = {
            "anchor_path": str(args.http_request_cleanup_anchors),
            "anchor_sha256": sha256_path(args.http_request_cleanup_anchors),
            "reopen_verification": str(args.http_request_cleanup_verification),
            "anchor_count": expected_http_request_cleanup,
            "verified_name_count": http_request_cleanup_verification["verified_name_count"],
            "reopen_failure_count": http_request_cleanup_verification["failure_count"],
        }
    if http_request_cleanup is not None:
        result["http_request_cleanup_anchors"] = http_request_cleanup
        result["interpretation"].append(
            "The v180 database revision also contains the separately reviewed HTTP request cleanup and properties destructor anchors."
        )
    tsocket_residual = None
    if args.tsocket_residual_anchors or args.tsocket_residual_verification:
        if not args.tsocket_residual_anchors or not args.tsocket_residual_verification:
            raise ValueError(
                "TSocket residual anchors and verification must be supplied together"
            )
        tsocket_residual_document = load(args.tsocket_residual_anchors)
        tsocket_residual_verification = load(args.tsocket_residual_verification)
        if tsocket_residual_document.get("artifact") != "spectron_tsocket_residual_manual_translation_anchors_20260827":
            raise ValueError("unexpected TSocket residual anchor artifact")
        if not tsocket_residual_verification.get("verified"):
            raise ValueError("TSocket residual anchor reopen verification did not pass")
        expected_tsocket_residual = len(tsocket_residual_document["anchors"])
        if tsocket_residual_verification["verified_name_count"] != expected_tsocket_residual:
            raise ValueError("TSocket residual verification count differs from artifact")
        tsocket_residual = {
            "anchor_path": str(args.tsocket_residual_anchors),
            "anchor_sha256": sha256_path(args.tsocket_residual_anchors),
            "reopen_verification": str(args.tsocket_residual_verification),
            "anchor_count": expected_tsocket_residual,
            "verified_name_count": tsocket_residual_verification["verified_name_count"],
            "reopen_failure_count": tsocket_residual_verification["failure_count"],
        }
    if tsocket_residual is not None:
        result["tsocket_residual_anchors"] = tsocket_residual
        result["interpretation"].append(
            "The v181 database revision also contains the separately reviewed TSocket client-list, destructor, error, and IP anchors."
        )
    game_environment = None
    if args.game_environment_anchors or args.game_environment_verification:
        if not args.game_environment_anchors or not args.game_environment_verification:
            raise ValueError(
                "game-environment anchors and verification must be supplied together"
            )
        game_environment_document = load(args.game_environment_anchors)
        game_environment_verification = load(args.game_environment_verification)
        if game_environment_document.get("artifact") != "spectron_game_environment_manual_translation_anchors_20260827":
            raise ValueError("unexpected game-environment anchor artifact")
        if not game_environment_verification.get("verified"):
            raise ValueError("game-environment anchor reopen verification did not pass")
        expected_game_environment = len(game_environment_document["anchors"])
        if game_environment_verification["verified_name_count"] != expected_game_environment:
            raise ValueError("game-environment verification count differs from artifact")
        game_environment = {
            "anchor_path": str(args.game_environment_anchors),
            "anchor_sha256": sha256_path(args.game_environment_anchors),
            "reopen_verification": str(args.game_environment_verification),
            "anchor_count": expected_game_environment,
            "verified_name_count": game_environment_verification["verified_name_count"],
            "reopen_failure_count": game_environment_verification["failure_count"],
        }
    if game_environment is not None:
        result["game_environment_anchors"] = game_environment
        result["interpretation"].append(
            "The v182 database revision also contains the separately reviewed TGameEnvironment property callback and startup-state anchors."
        )
    client_environment_graphics = None
    if args.client_environment_graphics_anchors or args.client_environment_graphics_verification:
        if not args.client_environment_graphics_anchors or not args.client_environment_graphics_verification:
            raise ValueError(
                "client-environment graphics anchors and verification must be supplied together"
            )
        client_environment_graphics_document = load(args.client_environment_graphics_anchors)
        client_environment_graphics_verification = load(
            args.client_environment_graphics_verification
        )
        if client_environment_graphics_document.get("artifact") != "spectron_client_environment_graphics_manual_translation_anchors_20260827":
            raise ValueError("unexpected client-environment graphics anchor artifact")
        if not client_environment_graphics_verification.get("verified"):
            raise ValueError(
                "client-environment graphics anchor reopen verification did not pass"
            )
        expected_client_environment_graphics = len(
            client_environment_graphics_document["anchors"]
        )
        if (
            client_environment_graphics_verification["verified_name_count"]
            != expected_client_environment_graphics
        ):
            raise ValueError(
                "client-environment graphics verification count differs from artifact"
            )
        client_environment_graphics = {
            "anchor_path": str(args.client_environment_graphics_anchors),
            "anchor_sha256": sha256_path(args.client_environment_graphics_anchors),
            "reopen_verification": str(args.client_environment_graphics_verification),
            "anchor_count": expected_client_environment_graphics,
            "verified_name_count": client_environment_graphics_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": client_environment_graphics_verification[
                "failure_count"
            ],
        }
    if client_environment_graphics is not None:
        result["client_environment_graphics_anchors"] = client_environment_graphics
        result["interpretation"].append(
            "The v183 database revision also contains the separately reviewed TClientEnvironment graphics initializer anchor."
        )
    client_environment_static_clear = None
    if (
        args.client_environment_static_clear_anchors
        or args.client_environment_static_clear_verification
    ):
        if (
            not args.client_environment_static_clear_anchors
            or not args.client_environment_static_clear_verification
        ):
            raise ValueError(
                "client-environment static-clear anchors and verification must be supplied together"
            )
        client_environment_static_clear_document = load(
            args.client_environment_static_clear_anchors
        )
        client_environment_static_clear_verification = load(
            args.client_environment_static_clear_verification
        )
        if (
            client_environment_static_clear_document.get("artifact")
            != "spectron_client_environment_static_clear_manual_translation_anchors_20260827"
        ):
            raise ValueError(
                "unexpected client-environment static-clear anchor artifact"
            )
        if not client_environment_static_clear_verification.get("verified"):
            raise ValueError(
                "client-environment static-clear anchor reopen verification did not pass"
            )
        expected_client_environment_static_clear = len(
            client_environment_static_clear_document["anchors"]
        )
        if (
            client_environment_static_clear_verification["verified_name_count"]
            != expected_client_environment_static_clear
        ):
            raise ValueError(
                "client-environment static-clear verification count differs from artifact"
            )
        client_environment_static_clear = {
            "anchor_path": str(args.client_environment_static_clear_anchors),
            "anchor_sha256": sha256_path(
                args.client_environment_static_clear_anchors
            ),
            "reopen_verification": str(
                args.client_environment_static_clear_verification
            ),
            "anchor_count": expected_client_environment_static_clear,
            "verified_name_count": client_environment_static_clear_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": client_environment_static_clear_verification[
                "failure_count"
            ],
        }
    if client_environment_static_clear is not None:
        result["client_environment_static_clear_anchors"] = (
            client_environment_static_clear
        )
        result["interpretation"].append(
            "The v184 database revision also contains the separately reviewed TClientEnvironment profiler-string cleanup anchors."
        )
    client_environment_restart_state = None
    if (
        args.client_environment_restart_state_anchors
        or args.client_environment_restart_state_verification
    ):
        if (
            not args.client_environment_restart_state_anchors
            or not args.client_environment_restart_state_verification
        ):
            raise ValueError(
                "client-environment restart-state anchors and verification must be supplied together"
            )
        client_environment_restart_state_document = load(
            args.client_environment_restart_state_anchors
        )
        client_environment_restart_state_verification = load(
            args.client_environment_restart_state_verification
        )
        if (
            client_environment_restart_state_document.get("artifact")
            != "spectron_client_environment_restart_state_manual_translation_anchors_20260827"
        ):
            raise ValueError(
                "unexpected client-environment restart-state anchor artifact"
            )
        if not client_environment_restart_state_verification.get("verified"):
            raise ValueError(
                "client-environment restart-state anchor reopen verification did not pass"
            )
        expected_client_environment_restart_state = len(
            client_environment_restart_state_document["anchors"]
        )
        if (
            client_environment_restart_state_verification["verified_name_count"]
            != expected_client_environment_restart_state
        ):
            raise ValueError(
                "client-environment restart-state verification count differs from artifact"
            )
        client_environment_restart_state = {
            "anchor_path": str(args.client_environment_restart_state_anchors),
            "anchor_sha256": sha256_path(
                args.client_environment_restart_state_anchors
            ),
            "reopen_verification": str(
                args.client_environment_restart_state_verification
            ),
            "anchor_count": expected_client_environment_restart_state,
            "verified_name_count": client_environment_restart_state_verification[
                "verified_name_count"
            ],
            "reopen_failure_count": client_environment_restart_state_verification[
                "failure_count"
            ],
        }
    if client_environment_restart_state is not None:
        result["client_environment_restart_state_anchors"] = (
            client_environment_restart_state
        )
        result["interpretation"].append(
            "The v185 database revision also contains the separately reviewed TClientEnvironment saved-restart cleanup anchor."
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), **result["translation"], "database_sha256": result["database"]["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
