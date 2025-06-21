import asyncio
import logging
import multiprocessing
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from config_loader import load_bot_config, print_config_summary
from trading.trader import PumpTrader
from utils.logger import setup_file_logging

def setup_logging(bot_name: str):
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = log_dir / f"{bot_name}_{timestamp}.log"
    setup_file_logging(str(log_filename))

async def start_bot(config_path: str):
    cfg = load_bot_config(config_path)
    setup_logging(cfg["name"])
    print_config_summary(cfg)

    trader = PumpTrader(
        rpc_endpoint=cfg["rpc_endpoint"],
        wss_endpoint=cfg["wss_endpoint"],
        private_key=cfg["private_key"],
        buy_amount=cfg["trade"]["buy_amount"],
        buy_slippage=cfg["trade"]["buy_slippage"],
        sell_slippage=cfg["trade"]["sell_slippage"],
        extreme_fast_mode=cfg["trade"].get("extreme_fast_mode", False),
        extreme_fast_token_amount=cfg["trade"].get("extreme_fast_token_amount", 30),
        exit_strategy=cfg["trade"].get("exit_strategy", "time_based"),
        take_profit_percentage=cfg["trade"].get("take_profit_percentage"),
        stop_loss_percentage=cfg["trade"].get("stop_loss_percentage"),
        max_hold_time=cfg["trade"].get("max_hold_time"),
        price_check_interval=cfg["trade"].get("price_check_interval", 10),
        listener_type=cfg["filters"]["listener_type"],
        geyser_endpoint=cfg.get("geyser", {}).get("endpoint"),
        geyser_api_token=cfg.get("geyser", {}).get("api_token"),
        geyser_auth_type=cfg.get("geyser", {}).get("auth_type"),
        pumpportal_url=cfg.get("pumpportal", {}).get("url", "wss://pumpportal.fun/api/data"),
        enable_dynamic_priority_fee=cfg.get("priority_fees", {}).get("enable_dynamic", False),
        enable_fixed_priority_fee=cfg.get("priority_fees", {}).get("enable_fixed", True),
        fixed_priority_fee=cfg.get("priority_fees", {}).get("fixed_amount", 500000),
        extra_priority_fee=cfg.get("priority_fees", {}).get("extra_percentage", 0.0),
        hard_cap_prior_fee=cfg.get("priority_fees", {}).get("hard_cap", 500000),
        max_retries=cfg.get("retries", {}).get("max_attempts", 10),
        wait_time_after_creation=cfg.get("retries", {}).get("wait_after_creation", 15),
        wait_time_after_buy=cfg.get("retries", {}).get("wait_after_buy", 15),
        wait_time_before_new_token=cfg.get("retries", {}).get("wait_before_new_token", 15),
        max_token_age=cfg.get("timing", {}).get("max_token_age", 0.001),
        token_wait_timeout=cfg.get("timing", {}).get("token_wait_timeout", 30),
        cleanup_mode=cfg.get("cleanup", {}).get("mode", "disabled"),
        cleanup_force_close_with_burn=cfg.get("cleanup", {}).get("force_close_with_burn", False),
        cleanup_with_priority_fee=cfg.get("cleanup", {}).get("with_priority_fee", False),
        match_string=cfg["filters"].get("match_string"),
        bro_address=cfg["filters"].get("bro_address"),
        marry_mode=cfg["filters"].get("marry_mode", False),
        yolo_mode=cfg["filters"].get("yolo_mode", False),
    )

    await trader.start()

def start_bot_process(config_path: str):
    asyncio.run(start_bot(config_path))

def run_all_bots():
    bot_dir = Path("bots")
    if not bot_dir.exists():
        logging.error(f"Bot directory '{bot_dir}' not found")
        return

    bot_files = list(bot_dir.glob("*.yaml"))
    if not bot_files:
        logging.error(f"No bot configuration files found in '{bot_dir}'")
        return

    logging.info(f"Found {len(bot_files)} bot configuration files")

    processes = []
    skipped_bots = 0

    for file in bot_files:
        try:
            cfg = load_bot_config(str(file))
            bot_name = cfg.get("name", file.stem)

            if not cfg.get("enabled", True):
                logging.info(f"Skipping disabled bot '{bot_name}'")
                skipped_bots += 1
                continue

            if cfg.get("separate_process", False):
                logging.info(f"Starting bot '{bot_name}' in separate process")
                p = multiprocessing.Process(
                    target=start_bot_process,
                    args=(str(file),),
                    name=f"bot-{bot_name}"
                )
                p.start()
                processes.append(p)
            else:
                logging.info(f"Starting bot '{bot_name}' in main process")
                asyncio.run(start_bot(str(file)))
        except Exception as e:
            logging.exception(f"Failed to start bot from {file}: {e}")

    logging.info(f"Started {len(bot_files) - skipped_bots} bots, skipped {skipped_bots} disabled bots")

    for p in processes:
        p.join()
        logging.info(f"Process {p.name} completed")

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    run_all_bots()

if __name__ == "__main__":
    main()
