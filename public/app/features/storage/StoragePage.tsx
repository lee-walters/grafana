import { css } from '@emotion/css';
import React, { useMemo, useState } from 'react';
import { useAsync } from 'react-use';

import { DataFrame, GrafanaTheme2, isDataFrame, ValueLinkConfig } from '@grafana/data';
import { locationService } from '@grafana/runtime';
import { useStyles2, IconName, Spinner, TabsBar, Tab, Button, HorizontalGroup } from '@grafana/ui';
import appEvents from 'app/core/app_events';
import { Page } from 'app/core/components/Page/Page';
import { useNavModel } from 'app/core/hooks/useNavModel';
import { GrafanaRouteComponentProps } from 'app/core/navigation/types';
import { ShowConfirmModalEvent } from 'app/types/events';

import { AddRootView } from './AddRootView';
import { Breadcrumb } from './Breadcrumb';
import { CreateNewFolderModal } from './CreateNewFolderModal';
import { ExportView } from './ExportView';
import { FileView } from './FileView';
import { FolderView } from './FolderView';
import { RootView } from './RootView';
import { getGrafanaStorage } from './helper';
import { StorageView } from './types';

interface RouteParams {
  path: string;
}

interface QueryParams {
  view: StorageView;
}

const folderNameRegex = /^[a-z\d!\-_.*'() ]+$/;
const folderNameMaxLength = 256;

interface Props extends GrafanaRouteComponentProps<RouteParams, QueryParams> {}

const getParentPath = (path: string) => {
  const lastSlashIdx = path.lastIndexOf('/');
  if (lastSlashIdx < 1) {
    return '';
  }

  return path.substring(0, lastSlashIdx);
};

export default function StoragePage(props: Props) {
  const styles = useStyles2(getStyles);
  const navModel = useNavModel('storage');
  const path = props.match.params.path ?? '';
  const view = props.queryParams.view ?? StorageView.Data;
  const setPath = (p: string, view?: StorageView) => {
    let url = ('/admin/storage/' + p).replace('//', '/');
    if (view && view !== StorageView.Data) {
      url += '?view=' + view;
    }
    locationService.push(url);
  };

  const [isAddingNewFolder, setIsAddingNewFolder] = useState(false);

  const listing = useAsync((): Promise<DataFrame | undefined> => {
    return getGrafanaStorage()
      .list(path)
      .then((frame) => {
        if (frame) {
          const name = frame.fields[0];
          frame.fields[0] = {
            ...name,
            getLinks: (cfg: ValueLinkConfig) => {
              const n = name.values.get(cfg.valueRowIndex ?? 0);
              const p = path + '/' + n;
              return [
                {
                  title: `Open ${n}`,
                  href: `/admin/storage/${p}`,
                  target: '_self',
                  origin: name,
                  onClick: () => {
                    setPath(p);
                  },
                },
              ];
            },
          };
        }
        return frame;
      });
  }, [path]);

  const isFolder = useMemo(() => {
    let isFolder = path?.indexOf('/') < 0;
    if (listing.value) {
      const length = listing.value.length;
      if (length === 1) {
        const first = listing.value.fields[0].values.get(0) as string;
        isFolder = !path.endsWith(first);
      } else {
        // TODO: handle files/folders which do not exist
        isFolder = true;
      }
    }
    return isFolder;
  }, [path, listing]);

  const fileNames = useMemo(() => {
    return (
      listing.value?.fields
        ?.find((f) => f.name === 'name')
        ?.values?.toArray()
        ?.filter((v) => typeof v === 'string') ?? []
    );
  }, [listing]);

  const renderView = () => {
    const isRoot = !path?.length || path === '/';
    switch (view) {
      case StorageView.Export:
        if (!isRoot) {
          setPath('');
          return <Spinner />;
        }
        return <ExportView onPathChange={setPath} />;

      case StorageView.AddRoot:
        if (!isRoot) {
          setPath('');
          return <Spinner />;
        }
        return <AddRootView onPathChange={setPath} />;
    }

    const frame = listing.value;
    if (!isDataFrame(frame)) {
      return <></>;
    }

    if (isRoot) {
      return <RootView root={frame} onPathChange={setPath} />;
    }

    const opts = [{ what: StorageView.Data, text: 'Data' }];

    // Root folders have a config page
    if (path.indexOf('/') < 0) {
      opts.push({ what: StorageView.Config, text: 'Configure' });
    }

    // Lets only apply permissions to folders (for now)
    if (isFolder) {
      opts.push({ what: StorageView.Perms, text: 'Permissions' });
    } else {
      // TODO: only if the file exists in a storage engine with
      opts.push({ what: StorageView.History, text: 'History' });
    }

    // Hardcode the uploadable folder :)
    if (isFolder && path.startsWith('resources')) {
      opts.push({
        what: StorageView.Upload,
        text: 'Upload',
      });
    }
    const canAddFolder = isFolder && path.startsWith('resources');
    const canDelete = path.startsWith('resources/');

    return (
      <div className={styles.wrapper}>
        <HorizontalGroup width="100%" justify="space-between" spacing={'md'} height={25}>
          <Breadcrumb pathName={path} onPathChange={setPath} rootIcon={navModel.node.icon as IconName} />
          <HorizontalGroup>
            {canAddFolder && <Button onClick={() => setIsAddingNewFolder(true)}>New Folder</Button>}
            {canDelete && (
              <Button
                variant="destructive"
                onClick={() => {
                  const text = isFolder
                    ? 'Are you sure you want to delete this folder and all its contents?'
                    : 'Are you sure you want to delete this file?';

                  const parentPath = getParentPath(path);
                  appEvents.publish(
                    new ShowConfirmModalEvent({
                      title: `Delete ${isFolder ? 'folder' : 'file'}`,
                      text,
                      icon: 'trash-alt',
                      yesText: 'Delete',
                      onConfirm: () =>
                        getGrafanaStorage()
                          .delete({ path, isFolder })
                          .then(() => {
                            setPath(parentPath);
                          }),
                    })
                  );
                }}
              >
                Delete
              </Button>
            )}
          </HorizontalGroup>
        </HorizontalGroup>

        <TabsBar>
          {opts.map((opt) => (
            <Tab
              key={opt.what}
              label={opt.text}
              active={opt.what === view}
              onChangeTab={() => setPath(path, opt.what)}
            />
          ))}
        </TabsBar>
        {isFolder ? (
          <FolderView path={path} listing={frame} onPathChange={setPath} view={view} />
        ) : (
          <FileView path={path} listing={frame} onPathChange={setPath} view={view} />
        )}

        {isAddingNewFolder && (
          <CreateNewFolderModal
            onSubmit={async ({ folderName }) => {
              const folderPath = `${path}/${folderName}`;
              const res = await getGrafanaStorage().createFolder(folderPath);
              if (typeof res?.error !== 'string') {
                setPath(folderPath);
                setIsAddingNewFolder(false);
              }
            }}
            onDismiss={() => {
              setIsAddingNewFolder(false);
            }}
            validate={(folderName) => {
              const lowerCase = folderName.toLowerCase();
              const trimmedLowerCase = lowerCase.trim();
              const existingTrimmedLowerCaseNames = fileNames.map((f) => f.trim().toLowerCase());

              if (existingTrimmedLowerCaseNames.includes(trimmedLowerCase)) {
                return 'A file or a folder with the same name already exists';
              }

              if (!folderNameRegex.test(lowerCase)) {
                return 'Name contains illegal characters';
              }

              if (folderName.length > folderNameMaxLength) {
                return `Name is too long, maximum length: ${folderNameMaxLength} characters`;
              }

              return true;
            }}
          />
        )}
      </div>
    );
  };

  return (
    <Page navModel={navModel}>
      <Page.Contents isLoading={listing.loading}>{renderView()}</Page.Contents>
    </Page>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  // TODO: remove `height: 90%`
  wrapper: css`
    display: flex;
    flex-direction: column;
    height: 100%;
  `,
  tableControlRowWrapper: css`
    display: flex;
    flex-direction: row;
    align-items: center;
    margin-bottom: ${theme.spacing(2)};
  `,
  // TODO: remove `height: 100%`
  tableWrapper: css`
    border: 1px solid ${theme.colors.border.medium};
    height: 100%;
  `,
  uploadSpot: css`
    margin-left: ${theme.spacing(2)};
  `,
  border: css`
    border: 1px solid ${theme.colors.border.medium};
    padding: ${theme.spacing(2)};
  `,
});
