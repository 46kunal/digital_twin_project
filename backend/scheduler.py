# scheduler.py
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import datetime

logger = logging.getLogger("scheduler")

scheduler = None

def scheduled_vm_scan(app):
    """Scan all VMs - runs daily at 2 AM"""
    with app.app_context():
        from models import db, VM, Scan
        from scanner import run_scan
        
        logger.info("Running scheduled VM scan")
        vms = VM.query.all()
        
        for vm in vms:
            try:
                # Create scan record
                new_scan = Scan(
                    target=vm.ip_address,
                    status='queued',
                    start_time=datetime.datetime.now(datetime.timezone.utc),
                    phase='scheduled'
                )
                db.session.add(new_scan)
                db.session.commit()
                
                # Run scan (this will be in background)
                run_scan(new_scan.id, vm.ip_address, mode='fast')
                logger.info(f"Scheduled scan started for {vm.ip_address}")
            except Exception as e:
                logger.exception(f"Scheduled scan failed for {vm.ip_address}: {e}")

def start_scheduler(app):
    """Initialize and start the background scheduler"""
    global scheduler
    
    if not app.config.get('SCHEDULER_ENABLED', True):
        logger.info("Scheduler is disabled")
        return
    
    scheduler = BackgroundScheduler()
    
    # Add job: Scan all VMs daily at 2 AM
    scheduler.add_job(
        func=lambda: scheduled_vm_scan(app),
        trigger=CronTrigger(hour=2, minute=0),
        id='daily_vm_scan',
        name='Daily VM Security Scan',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started - Daily scans at 2 AM")
    
    return scheduler

def stop_scheduler():
    """Gracefully stop the scheduler"""
    global scheduler
    if scheduler:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
