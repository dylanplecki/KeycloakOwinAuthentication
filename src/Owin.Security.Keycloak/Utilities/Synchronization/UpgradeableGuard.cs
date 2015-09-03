using System;
using System.Threading;

namespace Owin.Security.Keycloak.Utilities.Synchronization
{
    internal class UpgradeableGuard : IDisposable
    {
        private readonly ReaderWriterLockSlim _readerWriterLock;
        private UpgradedGuard _upgradedLock;

        public UpgradeableGuard(ReaderWriterLockSlim readerWriterLock)
        {
            _readerWriterLock = readerWriterLock;
            _readerWriterLock.EnterUpgradeableReadLock();
        }

        public void Dispose()
        {
            _upgradedLock?.Dispose();
            _readerWriterLock.ExitUpgradeableReadLock();
        }

        public IDisposable UpgradeToWriterLock()
        {
            return _upgradedLock ?? (_upgradedLock = new UpgradedGuard(this));
        }

        private class UpgradedGuard : IDisposable
        {
            private readonly UpgradeableGuard _parentGuard;
            private readonly WriterGuard _writerLock;

            public UpgradedGuard(UpgradeableGuard parentGuard)
            {
                _parentGuard = parentGuard;
                _writerLock = new WriterGuard(_parentGuard._readerWriterLock);
            }

            public void Dispose()
            {
                _writerLock.Dispose();
                _parentGuard._upgradedLock = null;
            }
        }
    }
}